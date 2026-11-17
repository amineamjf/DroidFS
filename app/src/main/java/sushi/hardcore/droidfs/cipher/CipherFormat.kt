package sushi.hardcore.droidfs.cipher

import java.io.IOException

/**
 * Standalone encrypted file format ("DFSC"), independent from gocryptfs and CryFS volumes.
 *
 * Layout (all integers big-endian):
 *
 * ```
 * offset  size  field
 * 0       4     magic "DFSC"
 * 4       1     format version (1)
 * 5       1     log2 of the plaintext chunk size (16 -> 64 KiB)
 * 6       2     reserved, must be 0
 * 8       12    key wrap nonce
 * 20      48    file key wrapped with the master key (32 bytes + 16 bytes GCM tag)
 * 68      7     stream nonce prefix
 * 75      4     metadata ciphertext length (L)
 * 79      12    metadata nonce
 * 91      L     metadata ciphertext (file name, size, mtime, mime type, padded) + GCM tag
 * 91+L    ...   chunks
 * ```
 *
 * Every chunk is AES-256-GCM encrypted with the per-file key. Chunk nonce =
 * stream prefix (7) || chunk counter (4) || last-chunk flag (1). A file always has at least one
 * chunk (empty files have a single empty last chunk), so truncation, extension and reordering
 * are detected. The additional data of each chunk is SHA-256 of the whole header, which binds
 * all chunks to the wrapped key and the encrypted metadata.
 *
 * Keys never leave the device: the master key is supplied by the caller and nothing here
 * performs any network operation.
 */
object CipherFormat {
    val MAGIC = byteArrayOf('D'.code.toByte(), 'F'.code.toByte(), 'S'.code.toByte(), 'C'.code.toByte())
    const val VERSION: Byte = 1
    const val CHUNK_SIZE_LOG2: Byte = 16
    const val CHUNK_SIZE = 1 shl 16

    const val KEY_SIZE = 32
    const val NONCE_SIZE = 12
    const val TAG_SIZE = 16
    const val STREAM_PREFIX_SIZE = 7

    const val FIXED_PREFIX_SIZE = 8
    const val WRAPPED_KEY_SIZE = KEY_SIZE + TAG_SIZE

    /** Upper bound for the metadata ciphertext, protects against huge allocations on tampered headers. */
    const val MAX_METADATA_CIPHERTEXT = 256 * 1024

    /** Offset of the 4-byte metadata ciphertext length field. */
    const val METADATA_LENGTH_OFFSET = FIXED_PREFIX_SIZE + NONCE_SIZE + WRAPPED_KEY_SIZE + STREAM_PREFIX_SIZE

    /** Total header size for a given metadata ciphertext length. */
    fun headerSize(metadataCiphertextLength: Int) = METADATA_LENGTH_OFFSET + 4 + NONCE_SIZE + metadataCiphertextLength

    const val CHUNK_CIPHERTEXT_SIZE = CHUNK_SIZE + TAG_SIZE
}

/** Base class of all errors raised by the cipher package. */
open class CipherException(message: String, cause: Throwable? = null) : IOException(message, cause)

/** The data is not a valid DFSC file (bad magic, unsupported version, truncated, malformed). */
class CipherFormatException(message: String) : CipherException(message)

/** A recovery code is malformed (wrong length, invalid characters or bad checksum, typically a typo). */
class InvalidRecoveryCodeException(message: String) : CipherException(message)

/** Authentication failed: wrong key, or the data has been modified. The two cases are not distinguishable. */
class CipherAuthException(message: String, cause: Throwable? = null) : CipherException(message, cause)
