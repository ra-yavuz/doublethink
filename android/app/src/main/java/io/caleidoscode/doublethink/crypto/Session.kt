package io.caleidoscode.doublethink.crypto

import java.security.SecureRandom

/** Which side of a two-party channel this device is, for the SEND direction. */
enum class Role { A, B }

/**
 * Per-channel payload crypto for one device.
 *
 * SEND uses a fixed role (the user's per-topic A/B choice): role A seals on aToB,
 * role B seals on bToA. The peer must hold the opposite role to read it. Two devices
 * on the SAME role cannot read each other - this is the documented two-party limit.
 *
 * RECEIVE auto-detects: [openAny] tries both direction keys. secretbox is an AEAD,
 * so the wrong key returns null cleanly and only the correct one yields plaintext.
 * This lets a device read the peer's traffic without the user choosing a receive
 * role, while keeping the send role explicit so sealing stays correct.
 */
class Session private constructor(
    private val sendKey: ByteArray,
    private val recvA: ByteArray,
    private val recvB: ByteArray,
) {
    private val rng = SecureRandom()

    /** Seal [plaintext] under this device's send key with a fresh random nonce. */
    fun seal(plaintext: ByteArray): ByteArray {
        val nonce = ByteArray(SecretBox.NONCE_BYTES)
        rng.nextBytes(nonce)
        return SecretBox.seal(sendKey, nonce, plaintext)
    }

    /**
     * Open a sealed blob, trying both per-direction keys. Returns the plaintext, or
     * null if neither key authenticates (wrong secret or tampered, or our own echo
     * sealed with our send key when send==one of the recv candidates).
     */
    fun openAny(blob: ByteArray): ByteArray? =
        SecretBox.open(recvA, blob) ?: SecretBox.open(recvB, blob)

    companion object {
        /**
         * Build a session for [secret] with the given SEND [role]. Receive tries both
         * directions regardless of role.
         */
        fun create(secret: String, role: Role): Session {
            val keys = ChannelCrypto.deriveBoth(secret)
            val sendKey = if (role == Role.A) keys.aToB else keys.bToA
            return Session(sendKey = sendKey, recvA = keys.aToB, recvB = keys.bToA)
        }
    }
}
