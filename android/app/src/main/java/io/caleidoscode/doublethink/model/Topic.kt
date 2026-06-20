package io.caleidoscode.doublethink.model

import io.caleidoscode.doublethink.crypto.Role

/** Whether a topic is an end-to-end-encrypted private channel or a plaintext one. */
enum class TopicMode { ENCRYPTED, PLAINTEXT }

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
