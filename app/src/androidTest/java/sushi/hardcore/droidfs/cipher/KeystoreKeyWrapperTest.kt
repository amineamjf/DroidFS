package sushi.hardcore.droidfs.cipher

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.security.SecureRandom

@RunWith(AndroidJUnit4::class)
class KeystoreKeyWrapperTest {
    private val suffix = SecureRandom().nextLong().toULong().toString(16)
    private val aliasA = "droidfs_test_a_$suffix"
    private val aliasB = "droidfs_test_b_$suffix"
    private val wrapperA = KeystoreKeyWrapper(aliasA)
    private val wrapperB = KeystoreKeyWrapper(aliasB)
    private val masterKey = ByteArray(32).also { SecureRandom().nextBytes(it) }

    @Before
    fun cleanBefore() {
        wrapperA.delete()
        wrapperB.delete()
    }

    @After
    fun cleanAfter() {
        wrapperA.delete()
        wrapperB.delete()
    }

    private inline fun <reified T : Throwable> assertThrows(message: String, block: () -> Unit) {
        try {
            block()
            fail("No exception: $message")
        } catch (e: Throwable) {
            if (e !is T) throw AssertionError("$message: expected ${T::class.java.simpleName} but got $e", e)
        }
    }

    @Test
    fun supported() {
        assertTrue(KeystoreKeyWrapper.isSupported())
    }

    @Test
    fun roundTrip() {
        assertFalse(wrapperA.hasKey())
        val blob = wrapperA.wrap(masterKey)
        assertTrue(wrapperA.hasKey())
        assertEquals(61, blob.size)
        assertArrayEquals(masterKey, wrapperA.unwrap(blob))
        // Wrapped blob does not contain the plain key
        assertTrue(blob.toList().windowed(32).none { it.toByteArray().contentEquals(masterKey) })
    }

    @Test
    fun keyIsNotExportable() {
        wrapperA.wrap(masterKey)
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = ks.getKey(aliasA, null)
        assertNull("Keystore key material must not be readable", key.encoded)
    }

    @Test
    fun wrappingIsRandomized() {
        val a = wrapperA.wrap(masterKey)
        val b = wrapperA.wrap(masterKey)
        assertFalse(a.contentEquals(b))
        assertArrayEquals(masterKey, wrapperA.unwrap(a))
        assertArrayEquals(masterKey, wrapperA.unwrap(b))
    }

    @Test
    fun otherAliasCannotUnwrap() {
        val blob = wrapperA.wrap(masterKey)
        wrapperB.wrap(ByteArray(32))
        assertThrows<CipherAuthException>("other key") { wrapperB.unwrap(blob) }
    }

    @Test
    fun deletedKeyCannotUnwrap() {
        val blob = wrapperA.wrap(masterKey)
        wrapperA.delete()
        assertFalse(wrapperA.hasKey())
        assertThrows<CipherAuthException>("deleted key") { wrapperA.unwrap(blob) }
        // A new key is created on demand and cannot open the old blob
        wrapperA.wrap(masterKey)
        assertThrows<CipherAuthException>("recreated key") { wrapperA.unwrap(blob) }
    }

    @Test
    fun everyModifiedByteIsRejected() {
        val blob = wrapperA.wrap(masterKey)
        for (i in blob.indices) {
            val tampered = blob.clone()
            tampered[i] = (tampered[i].toInt() xor 1).toByte()
            assertThrows<CipherException>("byte $i") { wrapperA.unwrap(tampered) }
        }
    }

    @Test
    fun malformedBlobsAreRejected() {
        wrapperA.wrap(masterKey)
        for (blob in listOf(ByteArray(0), ByteArray(60), ByteArray(62), ByteArray(61))) {
            assertThrows<CipherFormatException>("size ${blob.size}") { wrapperA.unwrap(blob) }
        }
    }

    @Test
    fun invalidKeySizeIsRejected() {
        try {
            wrapperA.wrap(ByteArray(16))
            fail()
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun keystoreWrappedKeyOpensFilesEncryptedWithVaultKey() {
        val created = MasterKeyVault.create("pw".toByteArray(), Argon2Params(1024, 1, 1))
        val data = ByteArray(100_000) { (it % 247).toByte() }
        val encrypted = ByteArrayOutputStream().also {
            FileCipher.encrypt(created.masterKey, ByteArrayInputStream(data), it, FileMetadata("a.txt", data.size.toLong()))
        }.toByteArray()

        val unwrapped = wrapperA.unwrap(wrapperA.wrap(created.masterKey))
        val out = ByteArrayOutputStream()
        FileCipher.decrypt(unwrapped, ByteArrayInputStream(encrypted), out)
        assertArrayEquals(data, out.toByteArray())
    }
}
