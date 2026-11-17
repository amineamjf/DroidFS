package sushi.hardcore.droidfs.cipher

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.SecureRandom
import sushi.hardcore.droidfs.cipher.CipherFormat as F

class FileCipherTest {
    private val random = SecureRandom()
    private val masterKey = ByteArray(F.KEY_SIZE).also { random.nextBytes(it) }

    private fun randomData(size: Int) = ByteArray(size).also { random.nextBytes(it) }

    private fun encrypt(data: ByteArray, metadata: FileMetadata = FileMetadata("a.bin", data.size.toLong()), key: ByteArray = masterKey): ByteArray {
        val out = ByteArrayOutputStream()
        FileCipher.encrypt(key, ByteArrayInputStream(data), out, metadata)
        return out.toByteArray()
    }

    private fun decrypt(encrypted: ByteArray, key: ByteArray = masterKey): Pair<ByteArray, FileMetadata> {
        val out = ByteArrayOutputStream()
        val metadata = FileCipher.decrypt(key, ByteArrayInputStream(encrypted), out)
        return Pair(out.toByteArray(), metadata)
    }

    private fun assertRejected(encrypted: ByteArray, message: String) {
        try {
            decrypt(encrypted)
            fail("Accepted invalid data: $message")
        } catch (_: CipherException) {
        }
    }

    private fun headerSize(encrypted: ByteArray): Int {
        val metadataLength = ByteBuffer.wrap(encrypted, F.METADATA_LENGTH_OFFSET, 4).getInt()
        return F.headerSize(metadataLength)
    }

    @Test
    fun roundTripAroundChunkBoundaries() {
        val c = F.CHUNK_SIZE
        for (size in listOf(0, 1, 100, c - 1, c, c + 1, 2 * c, 2 * c + 1, 3 * c + 12345)) {
            val data = randomData(size)
            val (decrypted, metadata) = decrypt(encrypt(data))
            assertArrayEquals("size $size", data, decrypted)
            assertEquals(size.toLong(), metadata.size)
        }
    }

    @Test
    fun ciphertextSizeIsPredictable() {
        val data = randomData(2 * F.CHUNK_SIZE + 10)
        val encrypted = encrypt(data)
        assertEquals(headerSize(encrypted) + data.size + 3 * F.TAG_SIZE, encrypted.size)
        // Empty file: a single empty last chunk
        val empty = encrypt(ByteArray(0))
        assertEquals(headerSize(empty) + F.TAG_SIZE, empty.size)
    }

    @Test
    fun metadataRoundTripWithUnicode() {
        val metadata = FileMetadata("تقرير سري ✓.pdf", 5, 1_700_000_000_000L, "application/pdf")
        val encrypted = encrypt(randomData(5), metadata)
        assertEquals(metadata, decrypt(encrypted).second)
        assertEquals(metadata, FileCipher.readMetadata(masterKey, ByteArrayInputStream(encrypted)))
    }

    @Test
    fun metadataIsPaddedAndHidden() {
        val short = encrypt(ByteArray(0), FileMetadata("a"))
        val longer = encrypt(ByteArray(0), FileMetadata("a".repeat(100)))
        assertEquals(short.size, longer.size)
        val secret = "very-secret-name.txt"
        val encrypted = encrypt(randomData(1000), FileMetadata(secret, 1000, 0, "text/plain"))
        assertEquals(-1, indexOf(encrypted, secret.toByteArray()))
        assertEquals(-1, indexOf(encrypted, "text/plain".toByteArray()))
    }

    @Test
    fun unknownSizeIsAccepted() {
        val data = randomData(777)
        val (decrypted, _) = decrypt(encrypt(data, FileMetadata("x")))
        assertArrayEquals(data, decrypted)
    }

    @Test
    fun sizeMismatchInMetadataIsRejected() {
        assertRejected(encrypt(randomData(10), FileMetadata("x", 11)), "wrong size in metadata")
    }

    @Test
    fun encryptionIsRandomized() {
        val data = randomData(500)
        assertFalse(encrypt(data).contentEquals(encrypt(data)))
    }

    @Test
    fun wrongKeyIsRejected() {
        val encrypted = encrypt(randomData(1000))
        val wrong = masterKey.clone().also { it[0] = (it[0].toInt() xor 1).toByte() }
        try {
            decrypt(encrypted, wrong)
            fail()
        } catch (_: CipherAuthException) {
        }
        try {
            FileCipher.readMetadata(wrong, ByteArrayInputStream(encrypted))
            fail()
        } catch (_: CipherAuthException) {
        }
    }

    @Test
    fun differentFilesHaveIndependentKeys() {
        // Two files encrypted under the same master key use different wrapped file keys.
        val a = encrypt(randomData(10))
        val b = encrypt(randomData(10))
        val wrapped = { e: ByteArray -> e.copyOfRange(F.FIXED_PREFIX_SIZE + F.NONCE_SIZE, F.FIXED_PREFIX_SIZE + F.NONCE_SIZE + F.WRAPPED_KEY_SIZE) }
        assertFalse(wrapped(a).contentEquals(wrapped(b)))
    }

    @Test
    fun everyBitFlipInSmallFileIsDetected() {
        val encrypted = encrypt(randomData(100))
        for (i in encrypted.indices) {
            for (bit in listOf(0, 7)) {
                val tampered = encrypted.clone()
                tampered[i] = (tampered[i].toInt() xor (1 shl bit)).toByte()
                assertRejected(tampered, "bit $bit of byte $i")
            }
        }
    }

    @Test
    fun bitFlipsInLargeFileAreDetected() {
        val encrypted = encrypt(randomData(3 * F.CHUNK_SIZE))
        val header = headerSize(encrypted)
        val offsets = mutableListOf<Int>()
        for (chunk in 0 until 3) {
            val start = header + chunk * F.CHUNK_CIPHERTEXT_SIZE
            offsets += listOf(start, start + 1, start + F.CHUNK_CIPHERTEXT_SIZE / 2, start + F.CHUNK_CIPHERTEXT_SIZE - 1)
        }
        for (i in offsets) {
            val tampered = encrypted.clone()
            tampered[i] = (tampered[i].toInt() xor 1).toByte()
            assertRejected(tampered, "byte $i")
        }
    }

    @Test
    fun truncationIsDetected() {
        val encrypted = encrypt(randomData(3 * F.CHUNK_SIZE))
        val header = headerSize(encrypted)
        assertRejected(encrypted.copyOf(encrypted.size - 1), "one byte missing")
        assertRejected(encrypted.copyOf(encrypted.size - F.TAG_SIZE), "tag missing")
        // Remove whole last chunk: the new last chunk was not encrypted as last
        assertRejected(encrypted.copyOf(encrypted.size - F.CHUNK_CIPHERTEXT_SIZE), "last chunk removed")
        assertRejected(encrypted.copyOf(header + F.CHUNK_CIPHERTEXT_SIZE), "only first chunk")
        assertRejected(encrypted.copyOf(header), "no chunks")
        assertRejected(encrypted.copyOf(10), "partial header")
        assertRejected(ByteArray(0), "empty input")
    }

    @Test
    fun trailingDataIsDetected() {
        val encrypted = encrypt(randomData(F.CHUNK_SIZE))
        assertRejected(encrypted + byteArrayOf(0), "one extra byte")
        assertRejected(encrypted + randomData(F.CHUNK_CIPHERTEXT_SIZE), "extra chunk")
        assertRejected(encrypted + encrypted, "concatenated files")
    }

    @Test
    fun chunkReorderingIsDetected() {
        val encrypted = encrypt(randomData(3 * F.CHUNK_SIZE))
        val header = headerSize(encrypted)
        val size = F.CHUNK_CIPHERTEXT_SIZE
        val reordered = encrypted.clone()
        System.arraycopy(encrypted, header + size, reordered, header, size)
        System.arraycopy(encrypted, header, reordered, header + size, size)
        assertRejected(reordered, "swapped chunks 0 and 1")
        val duplicated = encrypted.clone()
        System.arraycopy(encrypted, header, duplicated, header + size, size)
        assertRejected(duplicated, "duplicated chunk")
    }

    @Test
    fun chunksCannotBeTransplantedBetweenFiles() {
        val a = encrypt(randomData(2 * F.CHUNK_SIZE))
        val b = encrypt(randomData(2 * F.CHUNK_SIZE))
        val header = headerSize(a)
        assertEquals(header, headerSize(b))
        val mixed = a.clone()
        System.arraycopy(b, header, mixed, header, F.CHUNK_CIPHERTEXT_SIZE)
        assertRejected(mixed, "chunk from another file")
    }

    @Test
    fun invalidHeadersAreRejected() {
        val encrypted = encrypt(randomData(10))
        assertRejected(encrypted.clone().also { it[0] = 'X'.code.toByte() }, "bad magic")
        assertRejected(encrypted.clone().also { it[4] = 2 }, "unsupported version")
        assertRejected(encrypted.clone().also { it[5] = 12 }, "unsupported chunk size")
        assertRejected(encrypted.clone().also { it[6] = 1 }, "reserved bytes")
        val hugeMetadata = encrypted.clone()
        ByteBuffer.wrap(hugeMetadata).putInt(F.METADATA_LENGTH_OFFSET, Int.MAX_VALUE)
        assertRejected(hugeMetadata, "huge metadata length")
        val negativeMetadata = encrypted.clone()
        ByteBuffer.wrap(negativeMetadata).putInt(F.METADATA_LENGTH_OFFSET, -1)
        assertRejected(negativeMetadata, "negative metadata length")
    }

    @Test
    fun invalidMasterKeySizeIsRejected() {
        for (size in listOf(0, 16, 31, 33)) {
            try {
                encrypt(ByteArray(1), key = ByteArray(size))
                fail("size $size accepted")
            } catch (_: IllegalArgumentException) {
            }
        }
    }

    @Test
    fun metadataParserRejectsGarbage() {
        val valid = FileMetadata("n", 1, 2, "m").serialize()
        assertEquals(0, valid.size % FileMetadata.PADDING_BLOCK)
        for (data in listOf(ByteArray(0), ByteArray(3), ByteArray(64), randomData(64), valid.copyOf(10))) {
            try {
                FileMetadata.parse(data)
                if (!data.contentEquals(valid)) fail("accepted garbage")
            } catch (_: CipherFormatException) {
            }
        }
        assertNotEquals(0, valid.size)
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }
}
