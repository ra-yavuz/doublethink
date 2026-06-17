package broker

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/ra-yavuz/doublethink/internal/envelope"
)

func env(ch string, ty envelope.Type, id string) *envelope.Envelope {
	return &envelope.Envelope{
		Channel: ch,
		Type:    ty,
		ID:      id,
		Payload: json.RawMessage(`{}`),
		TS:      "2026-06-17T20:00:00Z",
	}
}

func recv(t *testing.T, sub *Subscription, within time.Duration) *envelope.Envelope {
	t.Helper()
	select {
	case e := <-sub.C:
		return e
	case <-sub.Closed:
		t.Fatal("subscription closed unexpectedly")
	case <-time.After(within):
		t.Fatal("timed out waiting for delivery")
	}
	return nil
}

// Fan-out: a published envelope reaches every current subscriber of the channel,
// and not subscribers of other channels.
func TestFanOutToChannelSubscribersOnly(t *testing.T) {
	b := New()
	a := b.Subscribe("chan-1")
	c := b.Subscribe("chan-1")
	other := b.Subscribe("chan-2")

	n := b.Publish(env("chan-1", envelope.TypeRequest, "r1"))
	if n != 2 {
		t.Fatalf("delivered to %d subscribers, want 2", n)
	}
	if got := recv(t, a, time.Second); got.ID != "r1" {
		t.Errorf("subscriber a got %q", got.ID)
	}
	if got := recv(t, c, time.Second); got.ID != "r1" {
		t.Errorf("subscriber c got %q", got.ID)
	}
	select {
	case e := <-other.C:
		t.Errorf("chan-2 subscriber wrongly received %q", e.ID)
	case <-time.After(50 * time.Millisecond):
		// correct: nothing for chan-2
	}
}

// Streaming: many progress messages arrive incrementally and in order at a
// connected subscriber, not batched (CONVERSATION-MODEL.md background tasks).
func TestStreamingIncrementalInOrder(t *testing.T) {
	b := New()
	sub := b.Subscribe("stream")

	const count = 50
	go func() {
		for i := 0; i < count; i++ {
			b.Publish(env("stream", envelope.TypeProgress, fmt.Sprintf("p%02d", i)))
		}
	}()

	for i := 0; i < count; i++ {
		got := recv(t, sub, time.Second)
		want := fmt.Sprintf("p%02d", i)
		if got.ID != want {
			t.Fatalf("message %d: got %q, want %q (order not preserved)", i, got.ID, want)
		}
	}
}

// Barge-in / no head-of-line blocking: a subscriber whose queue is completely
// full must not exert back-pressure on Publish, so a control message can still be
// fanned out to a healthy subscriber promptly. This is the property that lets a
// barge-in control reach a peer while a different, stalled peer is mid-stream.
//
// Written deterministically with NO scheduling dependence: the stalled
// subscriber is filled to exactly capacity, THEN a healthy subscriber joins (so
// it never receives the stalled peer's backlog), then we assert Publish of the
// control both returns promptly (does not block on the full subscriber) and
// reaches the healthy subscriber. The healthy subscriber's own queue holds only
// the single control message, so it cannot overflow.
func TestControlNotBlockedByFullSubscriber(t *testing.T) {
	b := New()
	stalled := b.Subscribe("room") // never drains; we fill it to capacity

	// Fill the stalled subscriber to exactly its queue capacity. After this its
	// buffered channel is full; the next publish to it would overflow and drop it.
	for i := 0; i < subscriberQueueDepth; i++ {
		b.Publish(env("room", envelope.TypeProgress, fmt.Sprintf("p%d", i)))
	}

	// A healthy peer joins now, so it never saw the backlog above. Its queue is
	// empty and will hold just the control message; it cannot overflow.
	healthy := b.Subscribe("room")

	// Publishing the control must return promptly (non-blocking per subscriber),
	// even though `stalled` is full. Time the call to prove it does not block.
	done := make(chan int, 1)
	go func() { done <- b.Publish(env("room", envelope.TypeControl, "barge-in")) }()
	select {
	case <-done:
		// Publish returned without blocking on the full subscriber. Good.
	case <-time.After(time.Second):
		t.Fatal("Publish blocked on a full subscriber; control would be stuck behind a stream")
	}

	// And the healthy subscriber actually received the control.
	select {
	case e := <-healthy.C:
		if e.Type != envelope.TypeControl || e.ID != "barge-in" {
			t.Errorf("healthy subscriber got %s/%q, want control/barge-in", e.Type, e.ID)
		}
	case <-healthy.Closed:
		t.Fatal("healthy subscriber was dropped; it had an empty queue and should not be")
	case <-time.After(time.Second):
		t.Fatal("control did not reach the healthy subscriber")
	}
	_ = stalled
}

// Liveness: a subscriber that stops draining and overflows its queue is dropped,
// rather than being allowed to block the sender or other subscribers forever.
func TestSlowSubscriberDropped(t *testing.T) {
	b := New()
	slow := b.Subscribe("c") // never drains

	// Publish well beyond the queue depth.
	for i := 0; i < subscriberQueueDepth+10; i++ {
		b.Publish(env("c", envelope.TypeProgress, fmt.Sprintf("m%d", i)))
	}

	select {
	case <-slow.Closed:
		// correct: overflowing subscriber was dropped
	case <-time.After(time.Second):
		t.Fatal("slow subscriber was not dropped after overflowing its queue")
	}
}

// Unsubscribe stops delivery and is idempotent.
func TestUnsubscribe(t *testing.T) {
	b := New()
	sub := b.Subscribe("c")
	if b.SubscriberCount("c") != 1 {
		t.Fatalf("subscriber count = %d, want 1", b.SubscriberCount("c"))
	}
	b.Unsubscribe(sub)
	if b.SubscriberCount("c") != 0 {
		t.Fatalf("subscriber count after unsubscribe = %d, want 0", b.SubscriberCount("c"))
	}
	b.Unsubscribe(sub) // idempotent, must not panic
	select {
	case <-sub.Closed:
	case <-time.After(time.Second):
		t.Fatal("Closed did not fire after Unsubscribe")
	}
}

// At-most-once online: a message published when nobody is subscribed reaches
// nobody, and a subscriber that joins afterward does not receive it (no replay).
func TestNoReplayForLateSubscriber(t *testing.T) {
	b := New()
	if n := b.Publish(env("c", envelope.TypeRequest, "early")); n != 0 {
		t.Fatalf("delivered to %d subscribers with none subscribed, want 0", n)
	}
	late := b.Subscribe("c")
	select {
	case e := <-late.C:
		t.Errorf("late subscriber received %q; M1 promises no replay", e.ID)
	case <-time.After(50 * time.Millisecond):
		// correct: at-most-once online, no retention in M1
	}
}
