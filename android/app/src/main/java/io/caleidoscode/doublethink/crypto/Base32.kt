package io.caleidoscode.doublethink.crypto

/**
 * RFC 4648 base32 with NO padding, matching the Go broker's encoding for the
 * channel secret S and the registration key (K_auth).
 *
 * Encode emits UPPERCASE (matching clientcrypto.GenerateSecret). Decode is
 * CASE-INSENSITIVE: the Go CLI displays a lowercased secret, and the broker's JS
 * demo uppercases before decoding, so a user may paste either case. Decoding must
 * accept both or a pasted lowercase secret silently fails to derive the right key.
 */
object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun encode(bytes: ByteArray): String {
        val sb = StringBuilder()
        var buffer = 0
        var bits = 0
        for (b in bytes) {
            buffer = (buffer shl 8) or (b.toInt() and 0xff)
            bits += 8
            while (bits >= 5) {
                sb.append(ALPHABET[(buffer ushr (bits - 5)) and 0x1f])
                bits -= 5
            }
        }
        if (bits > 0) {
            sb.append(ALPHABET[(buffer shl (5 - bits)) and 0x1f])
        }
        return sb.toString()
    }

    /**
     * Decode a base32 string, case-insensitively, ignoring any trailing '=' padding
     * and surrounding whitespace. Throws IllegalArgumentException on an invalid char.
     */
    fun decode(input: String): ByteArray {
        val s = input.trim().trimEnd('=').uppercase()
        val out = ArrayList<Byte>(s.length * 5 / 8)
        var buffer = 0
        var bits = 0
        for (c in s) {
            val idx = ALPHABET.indexOf(c)
            require(idx >= 0) { "invalid base32 character: $c" }
            buffer = (buffer shl 5) or idx
            bits += 5
            if (bits >= 8) {
                out.add(((buffer ushr (bits - 8)) and 0xff).toByte())
                bits -= 8
            }
        }
        return out.toByteArray()
    }
}
