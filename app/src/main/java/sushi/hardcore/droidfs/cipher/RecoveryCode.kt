package sushi.hardcore.droidfs.cipher

import java.security.MessageDigest

/**
 * Human-writable recovery code: 32 random bytes + 2 checksum bytes, Base32 (RFC 4648 alphabet),
 * 55 characters shown in groups of 5, e.g. `ABCDE-FGHIJ-...`.
 *
 * The checksum only detects typos (so the user can fix them); it adds no security.
 * Case, dashes and spaces are ignored when decoding.
 */
object RecoveryCode {
    const val SECRET_SIZE = 32
    private const val CHECKSUM_SIZE = 2
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private const val GROUP = 5

    fun encode(secret: ByteArray): String {
        require(secret.size == SECRET_SIZE)
        val data = secret + checksum(secret)
        val sb = StringBuilder()
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                sb.append(ALPHABET[(buffer shr (bits - 5)) and 31])
                bits -= 5
            }
            buffer = buffer and ((1 shl bits) - 1)
        }
        if (bits > 0) sb.append(ALPHABET[(buffer shl (5 - bits)) and 31])
        return sb.chunked(GROUP).joinToString("-")
    }

    /** @throws InvalidRecoveryCodeException if the code is malformed or mistyped */
    fun decode(code: String): ByteArray {
        val clean = code.filter { it != '-' && !it.isWhitespace() }.uppercase()
        val expectedChars = ((SECRET_SIZE + CHECKSUM_SIZE) * 8 + 4) / 5
        if (clean.length != expectedChars) throw InvalidRecoveryCodeException("Invalid recovery code length")
        val data = ByteArray(SECRET_SIZE + CHECKSUM_SIZE)
        var buffer = 0
        var bits = 0
        var index = 0
        for (c in clean) {
            val value = ALPHABET.indexOf(c)
            if (value < 0) throw InvalidRecoveryCodeException("Invalid character in recovery code")
            buffer = (buffer shl 5) or value
            bits += 5
            if (bits >= 8) {
                if (index < data.size) data[index++] = (buffer shr (bits - 8)).toByte()
                bits -= 8
                buffer = buffer and ((1 shl bits) - 1)
            }
        }
        if (index != data.size || buffer != 0) throw InvalidRecoveryCodeException("Invalid recovery code")
        val secret = data.copyOfRange(0, SECRET_SIZE)
        if (!checksum(secret).contentEquals(data.copyOfRange(SECRET_SIZE, data.size))) {
            secret.fill(0)
            throw InvalidRecoveryCodeException("Recovery code checksum mismatch")
        }
        return secret
    }

    private fun checksum(secret: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("DFSR".toByteArray())
        return digest.digest(secret).copyOf(CHECKSUM_SIZE)
    }
}
