package sushi.hardcore.droidfs.cipher

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/**
 * Metadata stored encrypted inside the file header, so nothing about the original file
 * (name, type, size, date) is visible in the ciphertext or in the name of the encrypted file.
 *
 * @param size original plaintext size, or -1 if unknown (then it is not verified on decryption)
 * @param modifiedMillis last modification time in milliseconds since epoch, 0 if unknown
 */
data class FileMetadata(
    val name: String,
    val size: Long = -1,
    val modifiedMillis: Long = 0,
    val mimeType: String = "",
) {
    /**
     * Serialized form: u32 payload length || payload || zero padding up to a multiple of
     * [PADDING_BLOCK], so the length of the name is not leaked.
     * Payload: u16 name length || name (UTF-8) || i64 size || i64 mtime || u16 mime length || mime (UTF-8).
     */
    fun serialize(): ByteArray {
        val nameBytes = name.toByteArray(StandardCharsets.UTF_8)
        val mimeBytes = mimeType.toByteArray(StandardCharsets.UTF_8)
        require(nameBytes.size <= MAX_FIELD) { "File name too long" }
        require(mimeBytes.size <= MAX_FIELD) { "MIME type too long" }
        val payloadSize = 2 + nameBytes.size + 8 + 8 + 2 + mimeBytes.size
        val total = (4 + payloadSize + PADDING_BLOCK - 1) / PADDING_BLOCK * PADDING_BLOCK
        val buffer = ByteBuffer.allocate(total) // zero-filled, so padding is zeros
        buffer.putInt(payloadSize)
        buffer.putShort(nameBytes.size.toShort())
        buffer.put(nameBytes)
        buffer.putLong(size)
        buffer.putLong(modifiedMillis)
        buffer.putShort(mimeBytes.size.toShort())
        buffer.put(mimeBytes)
        return buffer.array()
    }

    companion object {
        const val PADDING_BLOCK = 256
        private const val MAX_FIELD = 0xFFFF

        fun parse(data: ByteArray): FileMetadata {
            try {
                val buffer = ByteBuffer.wrap(data)
                val payloadSize = buffer.getInt()
                if (payloadSize < 20 || payloadSize > data.size - 4) {
                    throw CipherFormatException("Invalid metadata length")
                }
                val nameLength = buffer.getShort().toInt() and 0xFFFF
                val name = readString(buffer, nameLength, payloadSize)
                val size = buffer.getLong()
                val modified = buffer.getLong()
                val mimeLength = buffer.getShort().toInt() and 0xFFFF
                val mime = readString(buffer, mimeLength, payloadSize)
                if (buffer.position() != 4 + payloadSize) {
                    throw CipherFormatException("Invalid metadata structure")
                }
                if (size < -1) {
                    throw CipherFormatException("Invalid metadata size")
                }
                return FileMetadata(name, size, modified, mime)
            } catch (e: java.nio.BufferUnderflowException) {
                throw CipherFormatException("Truncated metadata")
            }
        }

        private fun readString(buffer: ByteBuffer, length: Int, payloadSize: Int): String {
            if (length > payloadSize || buffer.remaining() < length) {
                throw CipherFormatException("Invalid metadata field")
            }
            val bytes = ByteArray(length)
            buffer.get(bytes)
            return String(bytes, StandardCharsets.UTF_8)
        }
    }
}
