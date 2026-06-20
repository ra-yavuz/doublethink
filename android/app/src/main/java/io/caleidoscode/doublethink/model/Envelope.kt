package io.caleidoscode.doublethink.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * The doublethink wire envelope, matching internal/envelope/envelope.go exactly:
 * five fields, no more (the broker decodes with DisallowUnknownFields and rejects
 * any extra field). For a private channel, [payload] is base64 of the sealed blob
 * (nonce||ciphertext); for a plaintext topic it is a JSON string. The broker never
 * reshapes payload, so it must round-trip byte for byte.
 */
@Serializable
data class Envelope(
    @SerialName("channel") val channel: String,
    @SerialName("type") val type: String,
    @SerialName("id") val id: String,
    @SerialName("payload") val payload: String,
    @SerialName("ts") val ts: String,
) {
    fun encode(): String = OUTBOUND.encodeToString(serializer(), this)

    companion object {
        // Outbound: emit exactly the five fields, no nulls, no extras (broker is strict).
        private val OUTBOUND = Json { encodeDefaults = true; explicitNulls = false }

        // Inbound: tolerate odd shapes. The broker's own error frames carry an empty
        // channel/id and would fail a strict decode; we must not crash on them.
        private val INBOUND = Json { ignoreUnknownKeys = true; isLenient = true }

        fun decode(text: String): Envelope = INBOUND.decodeFromString(serializer(), text)
    }
}

/** The closed set of envelope types the broker accepts (envelope.go). */
object EnvelopeType {
    const val REQUEST = "request"
    const val PROGRESS = "progress"
    const val RESULT = "result"
    const val SUMMARY = "summary"
    const val CONTROL = "control"
    const val ERROR = "error"
}
