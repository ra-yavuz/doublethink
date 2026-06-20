package io.caleidoscode.doublethink.broker

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * The three small JSON frames of the WebSocket admission handshake, matching
 * internal/transport/transport.go (wsHandshake / wsChallenge / wsAuth / wsResult).
 * Client sends Hello, broker sends Challenge, client sends AuthResponse, broker
 * sends HandshakeResult. Pub/sub envelopes flow only after ok == true.
 */
@Serializable
data class WsHello(
    @SerialName("channel") val channel: String,
    @SerialName("after_seq") val afterSeq: Long? = null,
)

@Serializable
data class WsChallenge(
    @SerialName("challenge") val challenge: String, // base64 nonce
)

@Serializable
data class WsAuthResponse(
    @SerialName("response") val response: String, // base64 challenge response
)

@Serializable
data class WsResult(
    @SerialName("ok") val ok: Boolean = false,
    @SerialName("error") val error: String? = null,
)
