package io.caleidoscode.doublethink.crypto

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.Box as SodiumBox

/**
 * NaCl sealed boxes (crypto_box_seal: Curve25519 + XSalsa20-Poly1305), byte-compatible
 * with the Go broker's clientcrypto.SealTo/OpenSealed and the browser dt-sealedbox.js.
 *
 * This is the public-key counterpart to [SecretBox]'s shared-secret model. Anyone can
 * encrypt TO a published public key; only the holder of the private key can open it.
 * This is what lets a public web page (which can only ever hold a public key) send a
 * message that the broker operator and the public cannot read, openable solely on this
 * device. A fresh ephemeral keypair is used per message and discarded, so even the
 * sender cannot decrypt afterward.
 *
 * Wire layout: ephemeral_pub(32) || box(MAC(16) + ciphertext); overhead = 48 bytes.
 *
 * Honest limits: anonymous (no sender authenticity, so an open inbox is spam-able and
 * the recipient cannot verify who sent a message); losing the private key makes every
 * message sealed to the matching public key permanently unreadable.
 */
object SealedBox {
    const val PUBLICKEY_BYTES = 32
    const val SECRETKEY_BYTES = 32
    const val SEAL_BYTES = 48 // 32 ephemeral pubkey + 16 Poly1305 MAC

    private val sodium: LazySodiumAndroid by lazy { LazySodiumAndroid(SodiumAndroid()) }
    private val box: SodiumBox.Native by lazy { sodium as SodiumBox.Native }

    data class Keypair(val publicKey: ByteArray, val secretKey: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Keypair) return false
            return publicKey.contentEquals(other.publicKey) && secretKey.contentEquals(other.secretKey)
        }

        override fun hashCode(): Int = 31 * publicKey.contentHashCode() + secretKey.contentHashCode()
    }

    /** Generate a fresh Curve25519 keypair. The public key is safe to publish. */
    fun generateKeypair(): Keypair {
        val pk = ByteArray(PUBLICKEY_BYTES)
        val sk = ByteArray(SECRETKEY_BYTES)
        check(box.cryptoBoxKeypair(pk, sk)) { "box keypair generation failed" }
        return Keypair(pk, sk)
    }

    /**
     * Seal [message] to [recipientPublicKey]; returns ephemeral_pub || box. The sender
     * cannot decrypt the result (the ephemeral private key is discarded by libsodium).
     */
    fun seal(recipientPublicKey: ByteArray, message: ByteArray): ByteArray {
        require(recipientPublicKey.size == PUBLICKEY_BYTES) { "public key must be $PUBLICKEY_BYTES bytes" }
        val out = ByteArray(SEAL_BYTES + message.size)
        check(box.cryptoBoxSeal(out, message, message.size.toLong(), recipientPublicKey)) { "seal failed" }
        return out
    }

    /**
     * Open a sealed [blob] with this device's keypair. Returns the plaintext, or null
     * if it does not authenticate (wrong key, tampered, or truncated). Authenticated
     * decryption means garbage/spam on an open topic fails cleanly to null.
     */
    fun open(blob: ByteArray, publicKey: ByteArray, secretKey: ByteArray): ByteArray? {
        if (blob.size < SEAL_BYTES) return null
        val out = ByteArray(blob.size - SEAL_BYTES)
        val ok = box.cryptoBoxSealOpen(out, blob, blob.size.toLong(), publicKey, secretKey)
        return if (ok) out else null
    }
}
