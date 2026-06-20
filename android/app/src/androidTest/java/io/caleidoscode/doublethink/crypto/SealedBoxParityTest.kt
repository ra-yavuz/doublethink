package io.caleidoscode.doublethink.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Sealed-box (crypto_box_seal) parity, on-device because libsodium's native lib is
 * needed. The headline assertions are CROSS-language opens: a blob sealed by the GO
 * broker and a blob sealed by the BROWSER (JS) must both open with the Kotlin wrapper
 * using the recipient keypair from the golden vectors. If those pass, the whole
 * public-key path is byte-compatible across Go, JS, and Kotlin.
 */
@RunWith(AndroidJUnit4::class)
class SealedBoxParityTest {
    private val v: Map<String, String> by lazy {
        val ctx = InstrumentationRegistry.getInstrumentation().context
        parseFlatJson(ctx.assets.open("vectors.json").readBytes().toString(Charsets.UTF_8))
    }

    private fun b64(s: String): ByteArray = android.util.Base64.decode(s, android.util.Base64.DEFAULT)

    @Test
    fun opens_go_sealed_sample() {
        val pk = b64(v.getValue("box_recipient_pk_b64"))
        val sk = b64(v.getValue("box_recipient_sk_b64"))
        val opened = SealedBox.open(b64(v.getValue("box_sealed_by_go_b64")), pk, sk)
        assertNotNull("Kotlin must open the Go-sealed blob", opened)
        assertEquals(v.getValue("box_plaintext"), opened!!.toString(Charsets.UTF_8))
    }

    @Test
    fun opens_js_sealed_sample() {
        val pk = b64(v.getValue("box_recipient_pk_b64"))
        val sk = b64(v.getValue("box_recipient_sk_b64"))
        val opened = SealedBox.open(b64(v.getValue("box_sealed_by_js_b64")), pk, sk)
        assertNotNull("Kotlin must open the browser-sealed blob", opened)
        assertEquals(v.getValue("box_plaintext"), opened!!.toString(Charsets.UTF_8))
    }

    @Test
    fun opens_deterministic_vector() {
        // The exact-bytes deterministic blob (fixed ephemeral key) that Go and JS both
        // produce identically; Kotlin must open it, confirming the same nonce + layout.
        val pk = b64(v.getValue("box_recipient_pk_b64"))
        val sk = b64(v.getValue("box_recipient_sk_b64"))
        val opened = SealedBox.open(b64(v.getValue("box_sealed_deterministic_b64")), pk, sk)
        assertNotNull(opened)
        assertEquals(v.getValue("box_plaintext"), opened!!.toString(Charsets.UTF_8))
    }

    @Test
    fun roundtrip_and_length() {
        val kp = SealedBox.generateKeypair()
        val msg = "round trip".toByteArray(Charsets.UTF_8)
        val sealed = SealedBox.seal(kp.publicKey, msg)
        assertEquals(msg.size + SealedBox.SEAL_BYTES, sealed.size)
        assertArrayEquals(msg, SealedBox.open(sealed, kp.publicKey, kp.secretKey))
    }

    @Test
    fun wrong_key_returns_null() {
        val kp = SealedBox.generateKeypair()
        val other = SealedBox.generateKeypair()
        val sealed = SealedBox.seal(kp.publicKey, "secret".toByteArray())
        assertNull(SealedBox.open(sealed, other.publicKey, other.secretKey))
        assertNull(SealedBox.open(sealed.copyOf(sealed.size - 1), kp.publicKey, kp.secretKey))
    }

    private fun parseFlatJson(s: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        var i = 0
        fun skipWs() { while (i < s.length && s[i].isWhitespace()) i++ }
        fun readString(): String {
            check(s[i] == '"'); i++
            val sb = StringBuilder()
            while (i < s.length && s[i] != '"') {
                if (s[i] == '\\') { i++; sb.append(s[i]) } else sb.append(s[i])
                i++
            }
            i++
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
