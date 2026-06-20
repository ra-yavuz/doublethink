package io.caleidoscode.doublethink.broker

import java.security.SecureRandom
import kotlin.math.min

/**
 * Exponential backoff with full jitter, for per-topic reconnection. Full jitter
 * (a random delay in [0, cap]) avoids a thundering herd when the network flaps and
 * many topics reconnect at once. Reset to base after a clean, authenticated connect.
 */
class BackoffPolicy(
    private val baseMs: Long = 1_000,
    private val maxMs: Long = 60_000,
) {
    private val rng = SecureRandom()
    private var attempt = 0

    /** Next delay in ms, advancing the attempt counter. */
    fun nextDelayMs(): Long {
        val exp = min(maxMs, baseMs shl min(attempt, 20))
        attempt++
        // Full jitter: uniform in [0, exp].
        return (rng.nextDouble() * exp).toLong()
    }

    /** Call after a clean authenticated connect so the next failure starts from base. */
    fun reset() {
        attempt = 0
    }
}
