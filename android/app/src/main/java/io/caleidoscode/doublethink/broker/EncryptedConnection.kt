package io.caleidoscode.doublethink.broker

import android.util.Base64
import io.caleidoscode.doublethink.crypto.ChannelCrypto
import io.caleidoscode.doublethink.crypto.Role
import io.caleidoscode.doublethink.crypto.Session
import io.caleidoscode.doublethink.model.Envelope
import io.caleidoscode.doublethink.model.EnvelopeType
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.UUID

/**
 * One authenticated WebSocket attachment to a private channel, with the shared-secret
 * challenge/response handshake (transport.go) and end-to-end payload crypto. The
 * broker only ever sees ciphertext; this class seals on send and opens on receive.
 *
 * Lifecycle is a small state machine driven by inbound frames:
 *   open -> send Hello -> recv Challenge -> send AuthResponse -> recv ok -> STREAMING
 * Decrypted inbound messages and lifecycle events are delivered through [listener].
 * Reconnection is the caller's concern (ConnectionManager); this is a single attach.
 */
class EncryptedConnection(
    private val client: OkHttpClient,
    private val wsUrl: String,
    private val channelId: String,
    secret: String,
    sendRole: Role,
    private val afterSeq: Long?,
    private val listener: Listener,
) : WebSocketListener() {

    interface Listener {
        fun onAuthenticated() {}
        /** A decrypted inbound message; [envelopeId] is the wire id (for echo matching). */
        fun onMessage(envelopeId: String, type: String, plaintext: ByteArray?, raw: String) {}
        fun onClosed(reason: String) {}
        fun onFailure(t: Throwable?, reason: String) {}
    }

    private enum class Stage { AWAIT_CHALLENGE, AWAIT_OK, STREAMING, DEAD }

    private val secretRef = secret
    private val session: Session = Session.create(secret, sendRole)
    private val json = Json { ignoreUnknownKeys = true; isLenient = true }
    @Volatile private var stage = Stage.AWAIT_CHALLENGE
    @Volatile private var ws: WebSocket? = null

    fun connect() {
        val req = Request.Builder().url(wsUrl).build()
        ws = client.newWebSocket(req, this)
    }

    /** Seal [plaintext] and publish it; returns the envelope id used (for echo suppression), or null if not streaming. */
    fun send(plaintext: ByteArray, type: String = EnvelopeType.REQUEST): String? {
        val sock = ws ?: return null
        if (stage != Stage.STREAMING) return null
        val sealed = session.seal(plaintext)
        val id = UUID.randomUUID().toString()
        val env = Envelope(
            channel = channelId,
            type = type,
            id = id,
            payload = Base64.encodeToString(sealed, Base64.NO_WRAP),
            ts = nowRfc3339(),
        )
        return if (sock.send(env.encode())) id else null
    }

    fun close() {
        stage = Stage.DEAD
        ws?.close(1000, "client closing")
    }

    override fun onOpen(webSocket: WebSocket, response: Response) {
        // Stage 0: announce the channel. after_seq omitted (null) means from-current.
        val hello = WsHello(channel = channelId, afterSeq = afterSeq)
        webSocket.send(json.encodeToString(WsHello.serializer(), hello))
    }

    override fun onMessage(webSocket: WebSocket, text: String) {
        when (stage) {
            Stage.AWAIT_CHALLENGE -> {
                val ch = runCatching { json.decodeFromString(WsChallenge.serializer(), text) }.getOrNull()
                if (ch == null || ch.challenge.isEmpty()) {
                    fail(null, "bad challenge frame")
                    return
                }
                val challenge = Base64.decode(ch.challenge, Base64.DEFAULT)
                val resp = ChannelCrypto.challengeResponse(secretRef, challenge)
                val auth = WsAuthResponse(Base64.encodeToString(resp, Base64.NO_WRAP))
                webSocket.send(json.encodeToString(WsAuthResponse.serializer(), auth))
                stage = Stage.AWAIT_OK
            }
            Stage.AWAIT_OK -> {
                val res = runCatching { json.decodeFromString(WsResult.serializer(), text) }.getOrNull()
                if (res?.ok == true) {
                    stage = Stage.STREAMING
                    listener.onAuthenticated()
                } else {
                    // Fatal for this topic: wrong secret or unknown channel (uniform error).
                    fail(null, res?.error ?: "not authorized")
                    webSocket.close(1008, "not authorized")
                }
            }
            Stage.STREAMING -> handleEnvelope(text)
            Stage.DEAD -> { /* ignore */ }
        }
    }

    private fun handleEnvelope(text: String) {
        val env = runCatching { Envelope.decode(text) }.getOrNull() ?: return
        if (env.type == EnvelopeType.ERROR) {
            // A broker error frame (e.g. rate limited / invalid envelope). Surface but
            // do not treat as a normal message.
            listener.onMessage(env.id, env.type, null, text)
            return
        }
        val blob = runCatching { Base64.decode(env.payload, Base64.DEFAULT) }.getOrNull()
        val plaintext = blob?.let { session.openAny(it) }
        listener.onMessage(env.id, env.type, plaintext, text)
    }

    override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
        stage = Stage.DEAD
        webSocket.close(1000, null)
        listener.onClosed(reason.ifEmpty { "closed" })
    }

    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
        if (stage == Stage.DEAD) return
        fail(t, t.message ?: "connection failed")
    }

    private fun fail(t: Throwable?, reason: String) {
        if (stage == Stage.DEAD) return
        stage = Stage.DEAD
        listener.onFailure(t, reason)
    }

    private fun nowRfc3339(): String {
        // RFC3339 UTC, e.g. 2026-06-20T00:11:00Z. java.time is available on minSdk 26.
        return java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC)
            .format(java.time.format.DateTimeFormatter.ISO_OFFSET_DATE_TIME)
    }
}
