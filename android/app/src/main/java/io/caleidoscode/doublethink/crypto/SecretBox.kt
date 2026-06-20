package io.caleidoscode.doublethink.crypto

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.SecretBox as SodiumSecretBox

/**
 * NaCl secretbox (XSalsa20-Poly1305), byte-compatible with the Go broker's
 * clientcrypto (golang.org/x/crypto/nacl/secretbox) and the browser demo's
 * tweetnacl. libsodium's crypto_secretbox is the same construction as NaCl.
 *
 * Wire layout matches Go exactly: a sealed blob is nonce(24) || ciphertext, where
 * ciphertext is libsodium's MAC(16) || encrypted. Go's secretbox.Seal prepends the
 * nonce; libsodium's _easy returns only MAC||encrypted, so we concatenate the nonce
 * ourselves on seal and strip it on open.
 */
object SecretBox {
    const val KEY_BYTES = 32
    const val NONCE_BYTES = 24
    const val MAC_BYTES = 16

    private val sodium: LazySodiumAndroid by lazy { LazySodiumAndroid(SodiumAndroid()) }
    private val box: SodiumSecretBox.Native by lazy { sodium as SodiumSecretBox.Native }

    /** Seal [plaintext] under [key] with [nonce]; returns nonce || (mac || ciphertext). */
    fun seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        require(key.size == KEY_BYTES) { "key must be $KEY_BYTES bytes" }
        require(nonce.size == NONCE_BYTES) { "nonce must be $NONCE_BYTES bytes" }
        val ct = ByteArray(MAC_BYTES + plaintext.size)
        val ok = box.cryptoSecretBoxEasy(ct, plaintext, plaintext.size.toLong(), nonce, key)
        check(ok) { "secretbox seal failed" }
        return nonce + ct
    }

    /**
     * Open a nonce || (mac || ciphertext) [blob] under [key]. Returns the plaintext,
     * or null if authentication fails (wrong key or tampered) - secretbox is an AEAD,
     * so a wrong key fails cleanly, which is what makes receive role auto-detection
     * safe.
     */
    fun open(key: ByteArray, blob: ByteArray): ByteArray? {
        if (key.size != KEY_BYTES) return null
        if (blob.size < NONCE_BYTES + MAC_BYTES) return null
        val nonce = blob.copyOfRange(0, NONCE_BYTES)
        val ct = blob.copyOfRange(NONCE_BYTES, blob.size)
        val pt = ByteArray(ct.size - MAC_BYTES)
        val ok = box.cryptoSecretBoxOpenEasy(pt, ct, ct.size.toLong(), nonce, key)
        return if (ok) pt else null
    }
}
