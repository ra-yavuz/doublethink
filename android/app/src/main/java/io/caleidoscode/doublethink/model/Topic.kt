package io.caleidoscode.doublethink.model

import io.caleidoscode.doublethink.crypto.Role

/**
 * How a topic is secured:
 *  - ENCRYPTED: a two-party shared-secret private channel (WebSocket, symmetric).
 *  - PLAINTEXT: an open ntfy-style topic (SSE), no encryption.
 *  - SEALED: an open topic that carries sealed-box (public-key) ciphertext. Anyone
 *    can publish to it sealed to this device's public key; only this device, holding
 *    the private key, can open it. Receive-only on the phone (e.g. a contact inbox).
 */
enum class TopicMode { ENCRYPTED, PLAINTEXT, SEALED }

/**
 * A subscribed topic's configuration. The shared secret S is NOT stored here; it
 * lives in the EncryptedSharedPreferences vault keyed by [id]. Everything in this
 * object is non-secret routing/display metadata.
 *
 * [serverBaseUrl] defaults to the live public broker. [sendRole] applies only to
 * encrypted topics and selects which per-direction key seals outbound messages
 * (receive auto-detects). [lastSeenSeq] is the retained-channel catch-up cursor.
 */
data class Topic(
    val id: String,
    val displayName: String,
    val serverBaseUrl: String,
    val channelId: String,
    val mode: TopicMode,
    val sendRole: Role = Role.A,
    val showPreview: Boolean = true,
    val lastSeenSeq: Long = 0,
    val enabled: Boolean = true,
) {
    /** wss:// (or ws://) URL for the /ws endpoint, derived from [serverBaseUrl]. */
    fun wsUrl(): String {
        val base = serverBaseUrl.trimEnd('/')
        val scheme = if (base.startsWith("https://")) "wss://" + base.removePrefix("https://")
        else if (base.startsWith("http://")) "ws://" + base.removePrefix("http://")
        else base
        return "$scheme/ws"
    }

    companion object {
        const val DEFAULT_SERVER = "https://api.caleidoscode.io"
    }
}
