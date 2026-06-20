package io.caleidoscode.doublethink.crypto

import org.bouncycastle.crypto.digests.Blake2bDigest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter

/**
 * HKDF (RFC 5869) over HMAC-BLAKE2b-256, byte-identical to the Go broker's
 * clientcrypto.derive (which uses golang.org/x/crypto/hkdf with blake2b.New256).
 *
 * It is composed by hand over Bouncy Castle's HMAC-BLAKE2b rather than using
 * Bouncy Castle's HKDFBytesGenerator, because the extract step's treatment of an
 * empty salt is exactly where wrappers silently diverge. Go uses a zero key of the
 * hash OUTPUT size (32 bytes) when salt is nil; we replicate that explicitly here
 * and pin it with golden vectors generated from the Go side.
 *
 * BLAKE2b-256: output 32 bytes, block size 128 bytes (relevant only inside HMAC,
 * which Bouncy Castle handles).
 */
object HkdfBlake2b {
    const val HASH_LEN = 32

    /** Plain unkeyed BLAKE2b-256 of [data]. Must be the unkeyed digest. */
    fun blake2b256(data: ByteArray): ByteArray {
        val d = Blake2bDigest(256)
        d.update(data, 0, data.size)
        val out = ByteArray(d.digestSize)
        d.doFinal(out, 0)
        return out
    }

    /** HMAC-BLAKE2b-256 with [key] over [msg]. */
    fun hmac(key: ByteArray, msg: ByteArray): ByteArray {
        val mac = HMac(Blake2bDigest(256))
        mac.init(KeyParameter(key))
        mac.update(msg, 0, msg.size)
        val out = ByteArray(mac.macSize)
        mac.doFinal(out, 0)
        return out
    }

    /**
     * HKDF-Extract. A null or empty salt becomes HASH_LEN (32) zero bytes, matching
     * Go's hkdf.New extract step (zero key of the hash output size).
     */
    fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray {
        val s = if (salt == null || salt.isEmpty()) ByteArray(HASH_LEN) else salt
        return hmac(s, ikm)
    }

    /** HKDF-Expand to [length] bytes from a pseudorandom key [prk]. */
    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val out = ByteArray(length)
        var t = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            val mac = HMac(Blake2bDigest(256))
            mac.init(KeyParameter(prk))
            mac.update(t, 0, t.size)
            mac.update(info, 0, info.size)
            mac.update(byteArrayOf(counter.toByte()), 0, 1)
            t = ByteArray(mac.macSize)
            mac.doFinal(t, 0)
            val take = minOf(t.size, length - pos)
            System.arraycopy(t, 0, out, pos, take)
            pos += take
            counter++
        }
        return out
    }

    /** Full HKDF: extract then expand. info is a UTF-8 label. */
    fun derive(ikm: ByteArray, salt: ByteArray?, info: String, length: Int = HASH_LEN): ByteArray {
        val prk = extract(salt, ikm)
        return expand(prk, info.toByteArray(Charsets.UTF_8), length)
    }
}
