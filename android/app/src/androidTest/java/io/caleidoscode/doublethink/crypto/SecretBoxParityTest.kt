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
 * secretbox (XSalsa20-Poly1305) parity, on-device because libsodium's native lib is
 * needed. The headline assertion is the CROSS test: a blob sealed by the GO broker
 * (from the golden vector, role A's send key, fixed nonce) must open via the Kotlin
 * Session as role B's receive path. If this passes, the whole crypto stack is
 * compatible end to end, not just the hash layer.
 *
 * Vectors are read from the app assets (a copy of the unit-test vectors.json is
 * shipped as an asset so the instrumented test can read it on-device).
 */
@RunWith(AndroidJUnit4::class)
class SecretBoxParityTest {
    private val v: Map<String, String> by lazy {
        val ctx = InstrumentationRegistry.getInstrumentation().context
        val text = ctx.assets.open("vectors.json").readBytes().toString(Charsets.UTF_8)
        parseFlatJson(text)
    }

    private fun unhex(s: String) = ByteArray(s.length / 2) {
        s.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }
    private fun b64(s: String): ByteArray = android.util.Base64.decode(s, android.util.Base64.DEFAULT)

    @Test
    fun seal_then_open_roundtrips() {
        val key = unhex(v.getValue("key_a_to_b"))
        val nonce = unhex(v.getValue("secretbox_nonce"))
        val pt = v.getValue("secretbox_plaintext").toByteArray(Charsets.UTF_8)
        val sealed = SecretBox.seal(key, nonce, pt)
        val opened = SecretBox.open(key, sealed)
        assertNotNull(opened)
        assertArrayEquals(pt, opened)
    }

    @Test
    fun kotlin_seal_matches_go_sealed_bytes() {
        // Same key + same nonce + same plaintext must produce the exact Go blob.
        val key = unhex(v.getValue("key_a_to_b"))
        val nonce = unhex(v.getValue("secretbox_nonce"))
        val pt = v.getValue("secretbox_plaintext").toByteArray(Charsets.UTF_8)
        val sealed = SecretBox.seal(key, nonce, pt)
        assertArrayEquals(b64(v.getValue("secretbox_sealed_b64")), sealed)
    }

    @Test
    fun go_sealed_blob_opens_as_role_b_via_openAny() {
        // The headline cross test. Go sealed with role A's send key; a role B Session
        // must recover it through openAny (which tries both direction keys).
        val sessionB = Session.create(v.getValue("secret"), Role.B)
        val goBlob = b64(v.getValue("secretbox_sealed_b64"))
        val opened = sessionB.openAny(goBlob)
        assertNotNull("role B must open role A's Go-sealed blob", opened)
        assertEquals(v.getValue("secretbox_plaintext"), opened!!.toString(Charsets.UTF_8))
    }

    @Test
    fun wrong_secret_cannot_open() {
        val wrong = Session.create(ChannelCrypto.generateSecret(), Role.B)
        val goBlob = b64(v.getValue("secretbox_sealed_b64"))
        assertNull(wrong.openAny(goBlob))
    }

    private fun parseFlatJson(s: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        var i = 0
        fun skipWs() { while (i < s.length && s[i].isWhitespace()) i++ }
        fun readString(): String {
            check(s[i] == '"')
            i++
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
