package io.caleidoscode.doublethink.crypto

import java.security.SecureRandom

/**
 * Client-side derivation for a doublethink private channel, byte-identical to the Go
 * broker's internal/clientcrypto. Everything derives from one shared secret S
 * (base32) by HKDF over BLAKE2b-256 with domain-separated labels. S is NEVER sent
 * to the broker; only K_auth (as the registration key) and per-attach challenge
 * responses leave the device.
 *
 *   K_auth = HKDF(decode(S), salt=nil, info="doublethink-auth-v1")
 *   K_enc  = HKDF(decode(S), salt=nil, info="doublethink-enc-v1")
 *   aToB   = HKDF(K_enc, salt=nil, info="enc a->b")
 *   bToA   = HKDF(K_enc, salt=nil, info="enc b->a")
 *   challengeResponse = HKDF(K_auth, salt=challenge, info="doublethink-challenge-v1")
 */
object ChannelCrypto {
    private const val AUTH_TAG = "doublethink-auth-v1"
    private const val ENC_TAG = "doublethink-enc-v1"
    private const val CHALLENGE_TAG = "doublethink-challenge-v1"
    private const val SECRET_BYTES = 32

    private val rng = SecureRandom()

    /** A fresh 256-bit secret S, base32 (no pad), to be shared out of band. */
    fun generateSecret(): String {
        val raw = ByteArray(SECRET_BYTES)
        rng.nextBytes(raw)
        return Base32.encode(raw)
    }

    /** decode(S); throws if S is not valid base32 or is too short (< 16 bytes). */
    private fun decodeSecret(secret: String): ByteArray {
        val b = Base32.decode(secret)
        require(b.size >= 16) { "invalid channel secret" }
        return b
    }

    /** K_auth, the value the broker verifies attach challenges against. */
    fun authKey(secret: String): ByteArray =
        HkdfBlake2b.derive(decodeSecret(secret), null, AUTH_TAG)

    /** The base32 registration key (K_auth) sent ONCE at channel creation. */
    fun registrationKey(secret: String): String = Base32.encode(authKey(secret))

    /** The proof returned for a broker-issued challenge. */
    fun challengeResponse(secret: String, challenge: ByteArray): ByteArray =
        HkdfBlake2b.derive(authKey(secret), challenge, CHALLENGE_TAG)

    /** Both per-direction payload keys, derived from S. */
    fun deriveBoth(secret: String): DirectionKeys {
        val kEnc = HkdfBlake2b.derive(decodeSecret(secret), null, ENC_TAG)
        val aToB = HkdfBlake2b.derive(kEnc, null, "enc a->b")
        val bToA = HkdfBlake2b.derive(kEnc, null, "enc b->a")
        return DirectionKeys(aToB = aToB, bToA = bToA)
    }
}

data class DirectionKeys(val aToB: ByteArray, val bToA: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DirectionKeys) return false
        return aToB.contentEquals(other.aToB) && bToA.contentEquals(other.bToA)
    }

    override fun hashCode(): Int = 31 * aToB.contentHashCode() + bToA.contentHashCode()
}
