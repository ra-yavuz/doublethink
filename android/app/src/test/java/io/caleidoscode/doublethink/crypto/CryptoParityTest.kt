package io.caleidoscode.doublethink.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * Byte-for-byte parity against golden vectors emitted from the Go broker's
 * internal/clientcrypto (see .scratch/genvectors, output committed at
 * src/test/resources/vectors.json). Asserts bottom-up so a failure localizes to the
 * exact layer: BLAKE2b -> HKDF (extract/expand via the named derivations) -> K_auth
 * -> registration key -> challenge response -> K_enc -> per-direction keys.
 *
 * This is the make-or-break correctness gate. It is a PURE-JVM test (no Android, no
 * native lib): BLAKE2b/HMAC/HKDF/Base32 are all JVM-side. The secretbox round-trip
 * and the Go-sealed/Kotlin-opened cross test need libsodium's native lib and live in
 * the instrumented test (androidTest/SecretBoxParityTest).
 */
class CryptoParityTest {
    private val v: Map<String, String> by lazy {
        val stream = javaClass.getResourceAsStream("/vectors.json")
        assertNotNull("vectors.json must be on the test classpath", stream)
        parseFlatJson(stream!!.readBytes().toString(Charsets.UTF_8))
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = ByteArray(s.length / 2) {
        s.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }

    @Test
    fun base32_decodes_secret_to_expected_bytes() {
        val decoded = Base32.decode(v.getValue("secret"))
        assertEquals(v.getValue("secret_decoded"), hex(decoded))
    }

    @Test
    fun base32_decode_is_case_insensitive() {
        val upper = Base32.decode(v.getValue("secret"))
        val lower = Base32.decode(v.getValue("secret").lowercase())
        assertEquals(hex(upper), hex(lower))
    }

    @Test
    fun blake2b256_matches() {
        val decoded = Base32.decode(v.getValue("secret"))
        assertEquals(
            v.getValue("blake2b256_of_secret_decoded"),
            hex(HkdfBlake2b.blake2b256(decoded)),
        )
    }

    @Test
    fun k_auth_matches() {
        assertEquals(v.getValue("k_auth"), hex(ChannelCrypto.authKey(v.getValue("secret"))))
    }

    @Test
    fun registration_key_matches() {
        assertEquals(
            v.getValue("registration_key_b32"),
            ChannelCrypto.registrationKey(v.getValue("secret")),
        )
    }

    @Test
    fun challenge_response_matches() {
        val resp = ChannelCrypto.challengeResponse(
            v.getValue("secret"),
            unhex(v.getValue("challenge")),
        )
        assertEquals(v.getValue("challenge_response"), hex(resp))
    }

    @Test
    fun k_enc_matches() {
        val kEnc = HkdfBlake2b.derive(
            Base32.decode(v.getValue("secret")), null, "doublethink-enc-v1",
        )
        assertEquals(v.getValue("k_enc"), hex(kEnc))
    }

    @Test
    fun per_direction_keys_match() {
        val keys = ChannelCrypto.deriveBoth(v.getValue("secret"))
        assertEquals(v.getValue("key_a_to_b"), hex(keys.aToB))
        assertEquals(v.getValue("key_b_to_a"), hex(keys.bToA))
    }

    /**
     * Minimal flat JSON parser: the vectors file is a single object of string->string
     * (and one string value with spaces). Avoids a JSON dependency in the test.
     */
    private fun parseFlatJson(s: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        var i = 0
        fun skipWs() { while (i < s.length && s[i].isWhitespace()) i++ }
        fun readString(): String {
            check(s[i] == '"') { "expected string at $i" }
            i++
            val sb = StringBuilder()
            while (i < s.length && s[i] != '"') {
                if (s[i] == '\\') { i++; sb.append(s[i]) } else sb.append(s[i])
                i++
            }
            i++ // closing quote
            return sb.toString()
        }
        skipWs(); check(s[i] == '{'); i++
        while (true) {
            skipWs()
            if (s[i] == '}') break
            val key = readString()
            skipWs(); check(s[i] == ':'); i++; skipWs()
            val value = readString()
            out[key] = value
            skipWs()
            if (s[i] == ',') { i++; continue }
            if (s[i] == '}') break
        }
        return out
    }
}
