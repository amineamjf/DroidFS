package sushi.hardcore.droidfs.cipher

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import sushi.hardcore.droidfs.cipher.CipherFormat as F

/**
 * Streaming encryption and decryption of single files, see [CipherFormat] for the format.
 *
 * Streams are never closed by this class.
 *
 * Each chunk is authenticated before its plaintext is written, but earlier chunks may already
 * have been written when a later one fails. Callers decrypting to a destination file must write
 * to a temporary file and only rename it after [decrypt] returns successfully.
 */
object FileCipher {
    private val random = SecureRandom()

    /**
     * Encrypt [input] into [output].
     *
     * A fresh random key is generated for this file and wrapped with [masterKey].
     */
    fun encrypt(masterKey: ByteArray, input: InputStream, output: OutputStream, metadata: FileMetadata) {
        requireKeySize(masterKey)
        val fileKey = randomBytes(F.KEY_SIZE)
        try {
            val fixedPrefix = fixedPrefix()
            val wrapNonce = randomBytes(F.NONCE_SIZE)
            val wrappedKey = gcm(Cipher.ENCRYPT_MODE, masterKey, wrapNonce, fixedPrefix, fileKey)
            val streamPrefix = randomBytes(F.STREAM_PREFIX_SIZE)
            val metadataNonce = randomBytes(F.NONCE_SIZE)
            val metadataAad = fixedPrefix + wrapNonce + wrappedKey + streamPrefix
            val metadataCiphertext = gcm(Cipher.ENCRYPT_MODE, fileKey, metadataNonce, metadataAad, metadata.serialize())
            check(metadataCiphertext.size <= F.MAX_METADATA_CIPHERTEXT)

            val header = ByteArrayOutputStream().apply {
                write(metadataAad)
                write(ByteBuffer.allocate(4).putInt(metadataCiphertext.size).array())
                write(metadataNonce)
                write(metadataCiphertext)
            }.toByteArray()
            output.write(header)
            val chunkAad = sha256(header)

            val buffer = ByteArray(F.CHUNK_SIZE)
            var length = readFully(input, buffer, 0, buffer.size)
            var counter = 0L
            while (true) {
                // Look one byte ahead to know whether the current chunk is the last one.
                val lookAhead = if (length == buffer.size) input.read() else -1
                val last = lookAhead == -1
                val nonce = chunkNonce(streamPrefix, counter, last)
                output.write(gcm(Cipher.ENCRYPT_MODE, fileKey, nonce, chunkAad, buffer, 0, length))
                if (last) break
                buffer[0] = lookAhead.toByte()
                length = 1 + readFully(input, buffer, 1, buffer.size - 1)
                counter++
                if (counter > MAX_COUNTER) throw CipherException("File too large")
            }
            output.flush()
        } finally {
            fileKey.fill(0)
        }
    }

    /**
     * Decrypt [input] into [output].
     *
     * @return the decrypted metadata
     * @throws CipherAuthException if [masterKey] is wrong or the data has been modified
     * @throws CipherFormatException if the data is not a valid file
     */
    fun decrypt(masterKey: ByteArray, input: InputStream, output: OutputStream): FileMetadata {
        requireKeySize(masterKey)
        val header = readHeader(masterKey, input)
        try {
            val buffer = ByteArray(F.CHUNK_CIPHERTEXT_SIZE)
            var length = readFully(input, buffer, 0, buffer.size)
            if (length < F.TAG_SIZE) throw CipherFormatException("Truncated file")
            var counter = 0L
            var total = 0L
            while (true) {
                val lookAhead = if (length == buffer.size) input.read() else -1
                val last = lookAhead == -1
                val nonce = chunkNonce(header.streamPrefix, counter, last)
                val plaintext = gcmDecrypt(header.fileKey, nonce, header.chunkAad, buffer, 0, length)
                output.write(plaintext)
                total += plaintext.size
                plaintext.fill(0)
                if (last) break
                buffer[0] = lookAhead.toByte()
                length = 1 + readFully(input, buffer, 1, buffer.size - 1)
                if (length < F.TAG_SIZE) throw CipherFormatException("Truncated file")
                counter++
                if (counter > MAX_COUNTER) throw CipherFormatException("File too large")
            }
            output.flush()
            if (header.metadata.size >= 0 && header.metadata.size != total) {
                throw CipherFormatException("Size does not match metadata")
            }
            return header.metadata
        } finally {
            header.fileKey.fill(0)
        }
    }

    /** Read only the header and decrypt the metadata, without touching the file body. */
    fun readMetadata(masterKey: ByteArray, input: InputStream): FileMetadata {
        requireKeySize(masterKey)
        val header = readHeader(masterKey, input)
        header.fileKey.fill(0)
        return header.metadata
    }

    private class Header(
        val fileKey: ByteArray,
        val streamPrefix: ByteArray,
        val chunkAad: ByteArray,
        val metadata: FileMetadata,
    )

    private fun readHeader(masterKey: ByteArray, input: InputStream): Header {
        val fixedPrefix = readExactly(input, F.FIXED_PREFIX_SIZE)
        if (!fixedPrefix.copyOfRange(0, 4).contentEquals(F.MAGIC)) {
            throw CipherFormatException("Not a DFSC file")
        }
        if (fixedPrefix[4] != F.VERSION) throw CipherFormatException("Unsupported version ${fixedPrefix[4]}")
        if (fixedPrefix[5] != F.CHUNK_SIZE_LOG2) throw CipherFormatException("Unsupported chunk size")
        if (fixedPrefix[6].toInt() != 0 || fixedPrefix[7].toInt() != 0) throw CipherFormatException("Invalid header")

        val wrapNonce = readExactly(input, F.NONCE_SIZE)
        val wrappedKey = readExactly(input, F.WRAPPED_KEY_SIZE)
        val streamPrefix = readExactly(input, F.STREAM_PREFIX_SIZE)
        val metadataLengthBytes = readExactly(input, 4)
        val metadataLength = ByteBuffer.wrap(metadataLengthBytes).getInt()
        if (metadataLength < F.TAG_SIZE + 4 || metadataLength > F.MAX_METADATA_CIPHERTEXT) {
            throw CipherFormatException("Invalid metadata length")
        }
        val metadataNonce = readExactly(input, F.NONCE_SIZE)
        val metadataCiphertext = readExactly(input, metadataLength)

        val fileKey = gcmDecrypt(masterKey, wrapNonce, fixedPrefix, wrappedKey, 0, wrappedKey.size)
        try {
            val metadataAad = fixedPrefix + wrapNonce + wrappedKey + streamPrefix
            val metadataPlain = gcmDecrypt(fileKey, metadataNonce, metadataAad, metadataCiphertext, 0, metadataCiphertext.size)
            val metadata = try {
                FileMetadata.parse(metadataPlain)
            } finally {
                metadataPlain.fill(0)
            }
            val headerBytes = metadataAad + metadataLengthBytes + metadataNonce + metadataCiphertext
            return Header(fileKey, streamPrefix, sha256(headerBytes), metadata)
        } catch (e: Throwable) {
            fileKey.fill(0)
            throw e
        }
    }

    private const val MAX_COUNTER = 0xFFFFFFFFL

    private fun requireKeySize(key: ByteArray) {
        require(key.size == F.KEY_SIZE) { "Master key must be ${F.KEY_SIZE} bytes" }
    }

    private fun fixedPrefix(): ByteArray {
        return F.MAGIC + byteArrayOf(F.VERSION, F.CHUNK_SIZE_LOG2, 0, 0)
    }

    private fun chunkNonce(prefix: ByteArray, counter: Long, last: Boolean): ByteArray {
        val nonce = ByteArray(F.NONCE_SIZE)
        System.arraycopy(prefix, 0, nonce, 0, F.STREAM_PREFIX_SIZE)
        nonce[7] = (counter ushr 24).toByte()
        nonce[8] = (counter ushr 16).toByte()
        nonce[9] = (counter ushr 8).toByte()
        nonce[10] = counter.toByte()
        nonce[11] = if (last) 1 else 0
        return nonce
    }

    private fun gcm(mode: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray, data: ByteArray, offset: Int = 0, length: Int = data.size): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(F.TAG_SIZE * 8, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(data, offset, length)
    }

    private fun gcmDecrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, data: ByteArray, offset: Int, length: Int): ByteArray {
        try {
            return gcm(Cipher.DECRYPT_MODE, key, nonce, aad, data, offset, length)
        } catch (e: GeneralSecurityException) {
            throw CipherAuthException("Authentication failed: wrong key or corrupted data", e)
        }
    }

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    private fun randomBytes(size: Int) = ByteArray(size).also { random.nextBytes(it) }

    /** Read up to [length] bytes, returning fewer only at end of stream. */
    private fun readFully(input: InputStream, buffer: ByteArray, offset: Int, length: Int): Int {
        var total = 0
        while (total < length) {
            val read = input.read(buffer, offset + total, length - total)
            if (read < 0) break
            total += read
        }
        return total
    }

    private fun readExactly(input: InputStream, length: Int): ByteArray {
        val bytes = ByteArray(length)
        if (readFully(input, bytes, 0, length) != length) throw CipherFormatException("Truncated file")
        return bytes
    }
}
