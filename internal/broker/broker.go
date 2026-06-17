// Package broker is doublethink's in-memory pub/sub core: channels, subscriptions,
// and fan-out. It is deliberately payload-agnostic: it routes Envelopes on their
// channel/type/id/ts and forwards Payload bytes untouched, so it works identically
// whether a payload is plaintext (a public topic) or end-to-end-encrypted
// ciphertext (a private channel the broker cannot read).
//
// M1 delivery guarantee (docs/DESIGN-M1.md decision 6): at-most-once, online.
// A published envelope is fanned out to currently-connected subscribers; a peer
// offline at publish time misses it. Per-sender, per-channel order is preserved.
// Durable retention and at-least-once replay are a documented follow-up and are
// the reason Store is an interface seam rather than a hard-coded map.
package broker

import (
	"sync"

	"github.com/ra-yavuz/doublethink/internal/envelope"
)

// subscriberQueueDepth bounds how many envelopes may be buffered for one slow
// subscriber before the broker drops it. A per-subscriber queue is what stops a
// slow or streaming subscriber on one connection from blocking fan-out to the
// others, and is what lets a control message reach peer B promptly while peer A
// is mid progress-stream (DESIGN-M1.md decision 2, the barge-in case).
const subscriberQueueDepth = 256

// Subscription is a live subscriber's handle. C delivers envelopes in the order
// the broker fanned them out. The subscriber MUST drain C; a subscriber that
// stops draining and overflows its queue is dropped (Closed fires) rather than
// being allowed to stall the channel for everyone else.
type Subscription struct {
	C      <-chan *envelope.Envelope
	Closed <-chan struct{}

	id      uint64
	channel string
	out     chan *envelope.Envelope
	closed  chan struct{}
	once    sync.Once
}

// close tears down a subscription exactly once. Safe to call from the publish
// path (overflow drop) and from Unsubscribe (deliberate teardown).
func (s *Subscription) close() {
	s.once.Do(func() { close(s.closed) })
}

// Broker holds channels and their current subscribers. Public and private
// channels share this core; what differs (auth, encryption) lives in other
// packages, so the broker never has to know a channel's privacy mode to route it.
type Broker struct {
	mu     sync.Mutex
	nextID uint64
	subs   map[string]map[uint64]*Subscription // channel -> subscriber id -> sub
}

// New returns an empty broker.
func New() *Broker {
	return &Broker{subs: make(map[string]map[uint64]*Subscription)}
}

// Subscribe registers a subscriber on a channel and returns its Subscription.
// The caller reads from sub.C and must select on sub.Closed to learn it was
// dropped. Authorization (may this caller subscribe at all?) is the transport/
// auth layer's job and happens before Subscribe is ever called; the broker core
// trusts that gate, so name-secrecy is never the broker core's security model.
func (b *Broker) Subscribe(channel string) *Subscription {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.nextID++
	id := b.nextID
	out := make(chan *envelope.Envelope, subscriberQueueDepth)
	closed := make(chan struct{})
	sub := &Subscription{
		C:       out,
		Closed:  closed,
		id:      id,
		channel: channel,
		out:     out,
		closed:  closed,
	}

	if b.subs[channel] == nil {
		b.subs[channel] = make(map[uint64]*Subscription)
	}
	b.subs[channel][id] = sub
	return sub
}

// Unsubscribe removes a subscriber and closes its delivery. Idempotent.
func (b *Broker) Unsubscribe(sub *Subscription) {
	if sub == nil {
		return
	}
	b.mu.Lock()
	if m, ok := b.subs[sub.channel]; ok {
		if _, present := m[sub.id]; present {
			delete(m, sub.id)
			if len(m) == 0 {
				delete(b.subs, sub.channel)
			}
		}
	}
	b.mu.Unlock()
	sub.close()
}

// Publish fans an envelope out to every current subscriber of its channel. It
// returns the number of subscribers the envelope was delivered to (queued for).
//
// Ordering: under the lock we enqueue to each subscriber's buffered channel in a
// stable pass, so a single sender's sequence arrives in order at each subscriber.
// Non-blocking: if a subscriber's queue is full it is dropped (its Closed fires)
// rather than blocking the sender or the other subscribers. This is the explicit
// M1 choice: protect liveness of the channel over guaranteed delivery to a stalled
// peer (at-most-once, DESIGN-M1.md decision 6).
func (b *Broker) Publish(e *envelope.Envelope) int {
	b.mu.Lock()
	subscribers := b.subs[e.Channel]
	// Snapshot the current subscribers under the lock, then enqueue. Enqueue is a
	// non-blocking send into a buffered channel, so holding the lock across it is
	// bounded and keeps per-sender ordering deterministic.
	delivered := 0
	var toDrop []*Subscription
	for _, sub := range subscribers {
		select {
		case sub.out <- e:
			delivered++
		default:
			// Queue full: this subscriber is not keeping up. Mark for drop.
			toDrop = append(toDrop, sub)
		}
	}
	// Remove dropped subscribers while still holding the lock.
	for _, sub := range toDrop {
		if m, ok := b.subs[sub.channel]; ok {
			delete(m, sub.id)
			if len(m) == 0 {
				delete(b.subs, sub.channel)
			}
		}
	}
	b.mu.Unlock()

	// Close dropped subscribers outside the lock.
	for _, sub := range toDrop {
		sub.close()
	}
	return delivered
}

// SubscriberCount reports how many live subscribers a channel has. Test/introspection helper.
func (b *Broker) SubscriberCount(channel string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs[channel])
}
