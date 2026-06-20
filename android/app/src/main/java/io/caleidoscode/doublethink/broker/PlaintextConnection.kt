package io.caleidoscode.doublethink.broker

import io.caleidoscode.doublethink.model.Envelope
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.sse.EventSource
import okhttp3.sse.EventSourceListener
import okhttp3.sse.EventSources

/**
 * One Server-Sent-Events subscription to a plaintext (ntfy-style) topic:
 * GET <base>/subscribe/<topic>. Each SSE event's data is a full envelope JSON whose
 * payload is a JSON string (the published text). There is no secret and no decryption.
 *
 * Reconnection is the caller's concern (ConnectionManager); this is a single stream.
 */
class PlaintextConnection(
    private val client: OkHttpClient,
    private val baseUrl: String,
    private val topic: String,
    private val afterSeq: Long?,
    private val listener: Listener,
) : EventSourceListener() {

    interface Listener {
        fun onOpened() {}
        /** [seq] is the SSE id (retained topics only), or null for live-only frames. */
        fun onMessage(seq: Long?, envelopeId: String, text: String, raw: String) {}
        fun onClosed(reason: String) {}
        fun onFailure(t: Throwable?, reason: String) {}
    }

    private var source: EventSource? = null

    fun connect() {
        val url = buildString {
            append(baseUrl.trimEnd('/'))
            append("/subscribe/")
            append(topic)
            if (afterSeq != null && afterSeq > 0) append("?after=").append(afterSeq)
        }
        val req = Request.Builder().url(url).header("Accept", "text/event-stream").build()
        source = EventSources.createFactory(client).newEventSource(req, this)
    }

    fun close() {
        source?.cancel()
    }

    override fun onOpen(eventSource: EventSource, response: okhttp3.Response) {
        listener.onOpened()
    }

    override fun onEvent(eventSource: EventSource, id: String?, type: String?, data: String) {
        val seq = id?.toLongOrNull()
        val env = runCatching { Envelope.decode(data) }.getOrNull()
        if (env == null) {
            // Not a decodable envelope; deliver the raw data so nothing is silently dropped.
            listener.onMessage(seq, "", data, data)
            return
        }
        // The plaintext payload is a JSON string; unwrap it to the human text.
        val text = runCatching { kotlinx.serialization.json.Json.decodeFromString<String>(env.payload) }
            .getOrDefault(env.payload)
        listener.onMessage(seq, env.id, text, data)
    }

    override fun onClosed(eventSource: EventSource) {
        listener.onClosed("closed")
    }

    override fun onFailure(eventSource: EventSource, t: Throwable?, response: okhttp3.Response?) {
        val reason = when {
            response != null -> "http ${response.code}"
            t != null -> t.message ?: "connection failed"
            else -> "connection failed"
        }
        listener.onFailure(t, reason)
    }
}
