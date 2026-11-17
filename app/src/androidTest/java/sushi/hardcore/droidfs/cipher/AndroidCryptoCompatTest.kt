package sushi.hardcore.droidfs.cipher

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/**
 * The JVM unit tests run on the JDK crypto provider. These run the same core code on Android's
 * own provider (Conscrypt) and runtime, which is what the app uses.
 */
@RunWith(AndroidJUnit4::class)
class AndroidCryptoCompatTest {
    private val random = SecureRandom()
    private val key = ByteArray(32).also { random.nextBytes(it) }

    private fun encrypt(data: ByteArray) = ByteArrayOutputStream().also {
        FileCipher.encrypt(key, ByteArrayInputStream(data), it, FileMetadata("ملف.bin", data.size.toLong(), 123, "application/octet-stream"))
    }.toByteArray()

    @Test
    fun fileRoundTripOnAndroidProvider() {
        val c = CipherFormat.CHUNK_SIZE
        for (size in listOf(0, 1, c - 1, c, c + 1, 3 * c + 5)) {
            val data = ByteArray(size).also { random.nextBytes(it) }
            val out = ByteArrayOutputStream()
            val metadata = FileCipher.decrypt(key, ByteArrayInputStream(encrypt(data)), out)
            assertArrayEquals("size $size", data, out.toByteArray())
            assertEquals("ملف.bin", metadata.name)
        }
    }

    @Test
    fun tamperingAndTruncationDetectedOnAndroidProvider() {
        val encrypted = encrypt(ByteArray(2 * CipherFormat.CHUNK_SIZE + 10) { it.toByte() })
        val variants = listOf(
            encrypted.clone().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() },
            encrypted.clone().also { it[100] = (it[100].toInt() xor 1).toByte() },
            encrypted.copyOf(encrypted.size - 1),
            encrypted.copyOf(encrypted.size - CipherFormat.CHUNK_CIPHERTEXT_SIZE),
            encrypted + byteArrayOf(0),
        )
        for ((i, v) in variants.withIndex()) {
            try {
                FileCipher.decrypt(key, ByteArrayInputStream(v), ByteArrayOutputStream())
                fail("variant $i accepted")
            } catch (_: CipherException) {
            }
        }
    }

    @Test
    fun argon2idReferenceVectorOnAndroid() {
        val out = Argon2idKdf.derive("password".toByteArray(), "somesalt".toByteArray(), Argon2Params(65536, 2, 1))
        assertEquals("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7", out.joinToString("") { "%02x".format(it) })
    }

    @Test
    fun vaultOnAndroid() {
        val params = Argon2Params(1024, 1, 1)
        val created = MasterKeyVault.create("pw".toByteArray(), params)
        assertArrayEquals(created.masterKey, MasterKeyVault.unlockWithPassword(created.vault, "pw".toByteArray()))
        assertArrayEquals(created.masterKey, MasterKeyVault.unlockWithRecovery(created.vault, created.recoveryCode))
        val changed = MasterKeyVault.changePassword(created.vault, "pw".toByteArray(), "new".toByteArray(), params)
        assertArrayEquals(created.masterKey, MasterKeyVault.unlockWithPassword(changed, "new".toByteArray()))
        try {
            MasterKeyVault.unlockWithPassword(changed, "pw".toByteArray())
            fail()
        } catch (_: CipherAuthException) {
        }
    }

    @Test
    fun defaultArgon2ParametersRunOnEmulator() {
        // Memory and time sanity for the real default cost (64 MiB, 3 passes, 2 lanes).
        val start = System.nanoTime()
        val out = Argon2idKdf.derive("pw".toByteArray(), ByteArray(16), Argon2Params.DEFAULT)
        val ms = (System.nanoTime() - start) / 1_000_000
        assertEquals(32, out.size)
        android.util.Log.i("DroidFS", "Argon2id DEFAULT (64 MiB, 3 passes, 2 lanes) took $ms ms on ${android.os.Build.MODEL} API ${android.os.Build.VERSION.SDK_INT}")
    }
}
