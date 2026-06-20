package io.caleidoscode.doublethink.service

import io.caleidoscode.doublethink.broker.BackoffPolicy
import io.caleidoscode.doublethink.broker.EncryptedConnection
import io.caleidoscode.doublethink.broker.PlaintextConnection
import io.caleidoscode.doublethink.crypto.SealedBox
import io.caleidoscode.doublethink.model.Topic
import io.caleidoscode.doublethink.model.TopicMode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

/** Live connection status for a topic, surfaced to the UI. */
enum class ConnStatus { CONNECTING, CONNECTED, BACKING_OFF, FAILED }

/**
 * Owns one live connection per enabled topic and keeps them connected: it authenticates
 * (encrypted) or opens an SSE stream (plaintext), reconnects with jittered backoff on
 * transient drops, stops retrying on fatal errors (bad secret, channel-is-private), and
 * routes every inbound message that is NOT this app's own echo to [sink], deduped.
 *
 * It is transport-only: persistence (secrets, last-seen seq) and notifications are the
 * caller's concern, passed in as callbacks so this class stays testable without Android.
 */
class ConnectionManager(
    private val scope: CoroutineScope,
    private val client: OkHttpClient,
    private val secretFor: (Topic) -> String?,
    private val sink: MessageSink,
    // Returns the device sealed-box keypair, for SEALED inbox topics. Null disables
    // SEALED handling (those topics will report FAILED rather than leak ciphertext).
    private val boxKeypair: () -> io.caleidoscode.doublethink.crypto.SealedBox.Keypair? = { null },
) {
    /** What ConnectionManager emits upward (to the notifier + history store). */
    interface MessageSink {
        fun onStatus(topicId: String, status: ConnStatus, detail: String?) {}
        /** A fresh inbound message (own echoes and duplicates already filtered out). */
        fun onIncoming(topic: Topic, envelopeId: String, type: String, text: String?, decryptOk: Boolean, seq: Long?) {}
    }

    private val echo = OwnEchoRegistry()
    private val jobs = ConcurrentHashMap<String, Job>()
    private val encConns = ConcurrentHashMap<String, EncryptedConnection>()
    private val plainConns = ConcurrentHashMap<String, PlaintextConnection>()
    private val seenIds = ConcurrentHashMap<String, MutableSet<String>>()

    /** Bring connections in line with [topics] (start new, drop removed). Idempotent. */
    fun sync(topics: List<Topic>) {
        val wanted = topics.filter { it.enabled }.associateBy { it.id }
        // Stop connections for topics no longer wanted.
        jobs.keys.filter { it !in wanted }.forEach { stopTopic(it) }
        // Start connections for newly wanted topics.
        wanted.values.filter { !jobs.containsKey(it.id) }.forEach { startTopic(it) }
    }

    fun stopAll() {
        jobs.keys.toList().forEach { stopTopic(it) }
    }

    private fun stopTopic(topicId: String) {
        encConns.remove(topicId)?.close()
        plainConns.remove(topicId)?.close()
        jobs.remove(topicId)?.cancel()
        seenIds.remove(topicId)
    }

    private fun seenSet(topicId: String) =
        seenIds.getOrPut(topicId) { Collections.synchronizedSet(LinkedHashSet()) }

    /** Drop duplicate ids (catch-up + live can deliver the same message twice). */
    private fun firstSeen(topicId: String, id: String): Boolean {
        if (id.isEmpty()) return true
        val set = seenSet(topicId)
        synchronized(set) {
            if (!set.add(id)) return false
            if (set.size > 2000) { val it = set.iterator(); it.next(); it.remove() }
        }
        return true
    }

    private fun startTopic(topic: Topic) {
        val job = scope.launch {
            val backoff = BackoffPolicy()
            while (isActive) {
                val outcome = when (topic.mode) {
                    TopicMode.ENCRYPTED -> runEncrypted(topic, backoff)
                    TopicMode.PLAINTEXT -> runPlaintext(topic, backoff)
                    TopicMode.SEALED -> runSealed(topic, backoff)
                }
                if (outcome == Outcome.FATAL) {
                    sink.onStatus(topic.id, ConnStatus.FAILED, "stopped retrying")
                    return@launch
                }
                // Transient: back off, then loop to reconnect.
                sink.onStatus(topic.id, ConnStatus.BACKING_OFF, null)
                delay(backoff.nextDelayMs())
            }
        }
        jobs[topic.id] = job
    }

    private enum class Outcome { TRANSIENT, FATAL }

    /** Suspends until the encrypted connection closes; returns whether to retry. */
    private suspend fun runEncrypted(topic: Topic, backoff: BackoffPolicy): Outcome {
        val secret = secretFor(topic) ?: return Outcome.FATAL // no secret stored: cannot connect
        sink.onStatus(topic.id, ConnStatus.CONNECTING, null)
        val done = kotlinx.coroutines.CompletableDeferred<Outcome>()
        val conn = EncryptedConnection(
            client = client,
            wsUrl = topic.wsUrl(),
            channelId = topic.channelId,
            secret = secret,
            sendRole = topic.sendRole,
            afterSeq = topic.lastSeenSeq.takeIf { it > 0 },
            listener = object : EncryptedConnection.Listener {
                override fun onAuthenticated() {
                    backoff.reset()
                    sink.onStatus(topic.id, ConnStatus.CONNECTED, null)
                }
                override fun onMessage(envelopeId: String, type: String, plaintext: ByteArray?, raw: String) {
                    if (echo.isOwnEcho(topic.id, envelopeId)) return
                    if (!firstSeen(topic.id, envelopeId)) return
                    sink.onIncoming(
                        topic, envelopeId, type,
                        plaintext?.toString(Charsets.UTF_8), decryptOk = plaintext != null, seq = null,
                    )
                }
                override fun onClosed(reason: String) { if (!done.isCompleted) done.complete(Outcome.TRANSIENT) }
                override fun onFailure(t: Throwable?, reason: String) {
                    // Treat an auth rejection as fatal (wrong secret / unknown channel); other
                    // failures are transient and retried.
                    val fatal = reason.contains("not authorized", ignoreCase = true)
                    if (!done.isCompleted) done.complete(if (fatal) Outcome.FATAL else Outcome.TRANSIENT)
                }
            },
        )
        encConns[topic.id] = conn
        conn.connect()
        val result = done.await()
        encConns.remove(topic.id)
        conn.close()
        return result
    }

    private suspend fun runPlaintext(topic: Topic, backoff: BackoffPolicy): Outcome {
        sink.onStatus(topic.id, ConnStatus.CONNECTING, null)
        val done = kotlinx.coroutines.CompletableDeferred<Outcome>()
        val conn = PlaintextConnection(
            client = client,
            baseUrl = topic.serverBaseUrl,
            topic = topic.channelId,
            afterSeq = topic.lastSeenSeq.takeIf { it > 0 },
            listener = object : PlaintextConnection.Listener {
                override fun onOpened() {
                    backoff.reset()
                    sink.onStatus(topic.id, ConnStatus.CONNECTED, null)
                }
                override fun onMessage(seq: Long?, envelopeId: String, text: String, raw: String) {
                    // Plaintext echo suppression is heuristic (content+window); the broker
                    // discards our envelope id so id-matching is impossible here.
                    if (echo.isOwnEcho(topic.id, echo.contentToken(text))) return
                    val dedupKey = if (seq != null) "seq:$seq" else "txt:${echo.contentToken(text)}"
                    if (!firstSeen(topic.id, dedupKey)) return
                    sink.onIncoming(topic, envelopeId, "request", text, decryptOk = true, seq = seq)
                }
                override fun onClosed(reason: String) { if (!done.isCompleted) done.complete(Outcome.TRANSIENT) }
                override fun onFailure(t: Throwable?, reason: String) {
                    // 403 = the name is a registered private channel on the open path: fatal.
                    val fatal = reason.contains("403")
                    if (!done.isCompleted) done.complete(if (fatal) Outcome.FATAL else Outcome.TRANSIENT)
                }
            },
        )
        plainConns[topic.id] = conn
        conn.connect()
        val result = done.await()
        plainConns.remove(topic.id)
        conn.close()
        return result
    }

    /**
     * A SEALED topic is an open ntfy-style topic that carries sealed-box ciphertext.
     * It subscribes like a plaintext topic but base64-decodes each message and opens it
     * with this device's box keypair. Undecryptable inbound (spam or garbage anyone can
     * POST to an open topic) is dropped silently so it never raises a notification.
     */
    private suspend fun runSealed(topic: Topic, backoff: BackoffPolicy): Outcome {
        val kp = boxKeypair() ?: return Outcome.FATAL // no keypair: cannot open, do not leak
        sink.onStatus(topic.id, ConnStatus.CONNECTING, null)
        val done = kotlinx.coroutines.CompletableDeferred<Outcome>()
        val conn = PlaintextConnection(
            client = client,
            baseUrl = topic.serverBaseUrl,
            topic = topic.channelId,
            afterSeq = topic.lastSeenSeq.takeIf { it > 0 },
            listener = object : PlaintextConnection.Listener {
                override fun onOpened() {
                    backoff.reset()
                    sink.onStatus(topic.id, ConnStatus.CONNECTED, null)
                }
                override fun onMessage(seq: Long?, envelopeId: String, text: String, raw: String) {
                    val blob = runCatching { android.util.Base64.decode(text, android.util.Base64.DEFAULT) }.getOrNull()
                        ?: return // not base64: drop silently
                    val opened = blob.let { SealedBox.open(it, kp.publicKey, kp.secretKey) }
                        ?: return // does not authenticate (spam/garbage/wrong key): drop silently
                    val dedupKey = if (seq != null) "seq:$seq" else "txt:${echo.contentToken(text)}"
                    if (!firstSeen(topic.id, dedupKey)) return
                    // Sealed payload is the JSON {m,r,t}; surface m as the body. If it is
                    // not that shape, fall back to the raw decrypted text.
                    val body = parseSealedBody(opened.toString(Charsets.UTF_8))
                    sink.onIncoming(topic, envelopeId, "request", body, decryptOk = true, seq = seq)
                }
                override fun onClosed(reason: String) { if (!done.isCompleted) done.complete(Outcome.TRANSIENT) }
                override fun onFailure(t: Throwable?, reason: String) {
                    val fatal = reason.contains("403")
                    if (!done.isCompleted) done.complete(if (fatal) Outcome.FATAL else Outcome.TRANSIENT)
                }
            },
        )
        plainConns[topic.id] = conn
        conn.connect()
        val result = done.await()
        plainConns.remove(topic.id)
        conn.close()
        return result
    }

    /** Extract the human message from a sealed `{m,r,t}` payload; falls back to raw text. */
    private fun parseSealedBody(json: String): String {
        val parsed = runCatching {
            kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
                .parseToJsonElement(json)
        }.getOrNull() ?: return json
        val obj = (parsed as? kotlinx.serialization.json.JsonObject) ?: return json
        val m = (obj["m"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: return json
        val r = (obj["r"] as? kotlinx.serialization.json.JsonPrimitive)?.content
        return if (!r.isNullOrBlank()) "$m\n\nreply-to: $r" else m
    }

    /** Send on an encrypted topic; records the envelope id so its echo is suppressed. */
    fun sendEncrypted(topic: Topic, plaintext: ByteArray): Boolean {
        val conn = encConns[topic.id] ?: return false
        val id = conn.send(plaintext) ?: return false
        echo.record(topic.id, id)
        return true
    }

    /** Record a plaintext send for echo suppression (the HTTP POST is done by the caller). */
    fun recordPlaintextSend(topic: Topic, text: String) {
        echo.record(topic.id, echo.contentToken(text))
    }
}
