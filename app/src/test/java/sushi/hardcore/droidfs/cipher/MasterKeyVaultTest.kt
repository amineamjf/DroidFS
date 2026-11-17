package sushi.hardcore.droidfs.cipher

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class MasterKeyVaultTest {
    // Light parameters so tests are fast; DEFAULT is only checked for validity.
    private val fast = Argon2Params(1024, 1, 1)
    private val password = "correct horse battery staple".toByteArray()

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    private fun toHex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private inline fun <reified T : Throwable> assertThrows(message: String, block: () -> Unit) {
        try {
            block()
            fail("No exception: $message")
        } catch (e: Throwable) {
            if (e !is T) throw AssertionError("$message: expected ${T::class.java.simpleName} but got $e", e)
        }
    }

    @Test
    fun argon2idMatchesReferenceVector() {
        // Reference `argon2` CLI: echo -n password | argon2 somesalt -id -t 2 -m 16 -p 1 -l 32
        val out = Argon2idKdf.derive("password".toByteArray(), "somesalt".toByteArray(), Argon2Params(65536, 2, 1))
        assertEquals("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7", toHex(out))
    }

    @Test
    fun hkdfMatchesRfc5869TestCase3() {
        // RFC 5869 A.3: IKM = 22 x 0x0b, empty salt, empty info; first block of OKM
        val okm = MasterKeyVault.hkdfSha256(ByteArray(22) { 0x0b }, ByteArray(0))
        assertEquals("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d", toHex(okm))
    }

    @Test
    fun defaultParametersAreValid() {
        assertTrue(Argon2Params.isValid(Argon2Params.DEFAULT.memoryKiB.toLong(), Argon2Params.DEFAULT.iterations.toLong(), Argon2Params.DEFAULT.parallelism.toLong()))
    }

    @Test
    fun passwordAndRecoveryUnlockTheSameKey() {
        val created = MasterKeyVault.create(password, fast)
        assertEquals(32, created.masterKey.size)
        assertArrayEquals(created.masterKey, MasterKeyVault.unlockWithPassword(created.vault, password))
        assertArrayEquals(created.masterKey, MasterKeyVault.unlockWithRecovery(created.vault, created.recoveryCode))
    }

    @Test
    fun wrongPasswordIsRejected() {
        val created = MasterKeyVault.create(password, fast)
        assertThrows<CipherAuthException>("wrong password") { MasterKeyVault.unlockWithPassword(created.vault, "wrong".toByteArray()) }
        assertThrows<CipherAuthException>("empty password") { MasterKeyVault.unlockWithPassword(created.vault, ByteArray(0)) }
    }

    @Test
    fun emptyPasswordCannotBeSet() {
        try {
            MasterKeyVault.create(ByteArray(0), fast)
            fail()
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun recoveryCodeToleratesFormatting() {
        val created = MasterKeyVault.create(password, fast)
        val sloppy = " " + created.recoveryCode.lowercase().replace("-", " ") + "\n"
        assertArrayEquals(created.masterKey, MasterKeyVault.unlockWithRecovery(created.vault, sloppy))
    }

    @Test
    fun recoveryCodeFromAnotherVaultIsRejected() {
        val a = MasterKeyVault.create(password, fast)
        val b = MasterKeyVault.create(password, fast)
        assertThrows<CipherAuthException>("other vault code") { MasterKeyVault.unlockWithRecovery(a.vault, b.recoveryCode) }
    }

    @Test
    fun mistypedRecoveryCodeIsReportedAsTypo() {
        val created = MasterKeyVault.create(password, fast)
        // Fixed secret: the checksum outcome is deterministic, not random per run
        val code = RecoveryCode.encode(ByteArray(32) { (it * 5 + 1).toByte() })
        val i = code.indexOfFirst { it != '-' }
        val replacement = if (code[i] == 'A') 'B' else 'A'
        val typo = code.substring(0, i) + replacement + code.substring(i + 1)
        assertThrows<InvalidRecoveryCodeException>("typo") { MasterKeyVault.unlockWithRecovery(created.vault, typo) }
        assertThrows<InvalidRecoveryCodeException>("too short") { MasterKeyVault.unlockWithRecovery(created.vault, code.dropLast(1)) }
        assertThrows<InvalidRecoveryCodeException>("invalid char") { MasterKeyVault.unlockWithRecovery(created.vault, code.replaceFirst(code[0], '1')) }
        assertThrows<InvalidRecoveryCodeException>("empty") { MasterKeyVault.unlockWithRecovery(created.vault, "") }
    }

    @Test
    fun recoveryCodeRoundTripAndShape() {
        val secret = ByteArray(32) { (it * 7 + 3).toByte() }
        val code = RecoveryCode.encode(secret)
        assertEquals(55 + 10, code.length) // 55 chars + 10 dashes (11 groups of 5)
        assertTrue(code.all { it == '-' || it in 'A'..'Z' || it in '2'..'7' })
        assertArrayEquals(secret, RecoveryCode.decode(code))
        // Every single-character substitution of a fixed code must be caught (deterministic)
        val plain = code.replace("-", "")
        for (pos in plain.indices) {
            for (c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") {
                if (c == plain[pos]) continue
                val mutated = plain.substring(0, pos) + c + plain.substring(pos + 1)
                assertThrows<InvalidRecoveryCodeException>("substitution at $pos with $c") { RecoveryCode.decode(mutated) }
            }
        }
    }

    @Test
    fun recoveryCodesAreRandom() {
        val a = MasterKeyVault.create(password, fast)
        val b = MasterKeyVault.create(password, fast)
        assertFalse(a.recoveryCode == b.recoveryCode)
        assertFalse(a.masterKey.contentEquals(b.masterKey))
    }

    @Test
    fun changePasswordKeepsMasterKeyAndRecovery() {
        val created = MasterKeyVault.create(password, fast)
        val newPassword = "new password".toByteArray()
        val updated = MasterKeyVault.changePassword(created.vault, password, newPassword, fast)
        assertFalse(updated.contentEquals(created.vault))
        assertThrows<CipherAuthException>("old password") { MasterKeyVault.unlockWithPassword(updated, password) }
        assertArrayEquals(created.masterKey, MasterKeyVault.unlockWithPassword(updated, newPassword))
        assertArrayEquals(created.masterKey, MasterKeyVault.unlockWithRecovery(updated, created.recoveryCode))
        assertThrows<CipherAuthException>("wrong old password") { MasterKeyVault.changePassword(created.vault, "nope".toByteArray(), newPassword, fast) }
    }

    @Test
    fun forgottenPasswordCanBeResetWithRecoveryCode() {
        val created = MasterKeyVault.create(password, fast)
        val newPassword = "after reset".toByteArray()
        val updated = MasterKeyVault.resetPasswordWithRecovery(created.vault, created.recoveryCode, newPassword, fast)
        assertArrayEquals(created.masterKey, MasterKeyVault.unlockWithPassword(updated, newPassword))
        assertThrows<CipherAuthException>("old password") { MasterKeyVault.unlockWithPassword(updated, password) }
        assertArrayEquals(created.masterKey, MasterKeyVault.unlockWithRecovery(updated, created.recoveryCode))
    }

    @Test
    fun rotatingRecoveryInvalidatesOldCode() {
        val created = MasterKeyVault.create(password, fast)
        val (rotated, newCode) = MasterKeyVault.rotateRecovery(created.vault, password)
        assertFalse(newCode == created.recoveryCode)
        assertThrows<CipherAuthException>("old code") { MasterKeyVault.unlockWithRecovery(rotated, created.recoveryCode) }
        assertArrayEquals(created.masterKey, MasterKeyVault.unlockWithRecovery(rotated, newCode))
        assertArrayEquals(created.masterKey, MasterKeyVault.unlockWithPassword(rotated, password))
        assertThrows<CipherAuthException>("wrong password") { MasterKeyVault.rotateRecovery(created.vault, "nope".toByteArray()) }
    }

    @Test
    fun tamperedPasswordSlotIsRejected() {
        val created = MasterKeyVault.create(password, fast)
        val start = 6
        val end = 6 + 86
        // Flip bit 0 (and bit 7 outside the Argon2 cost fields) of every byte of the password slot.
        for (i in 0 until end) {
            val bits = if (i in 7..15) listOf(0) else listOf(0, 7)
            for (bit in bits) {
                val tampered = created.vault.clone()
                tampered[i] = (tampered[i].toInt() xor (1 shl bit)).toByte()
                assertThrows<CipherException>("byte $i bit $bit") { MasterKeyVault.unlockWithPassword(tampered, password) }
            }
        }
        assertTrue(end > start)
    }

    @Test
    fun tamperedRecoverySlotIsRejected() {
        val created = MasterKeyVault.create(password, fast)
        for (i in 0 until created.vault.size) {
            if (i in 6 until 6 + 86) continue // password slot does not influence recovery unlock
            for (bit in listOf(0, 7)) {
                val tampered = created.vault.clone()
                tampered[i] = (tampered[i].toInt() xor (1 shl bit)).toByte()
                assertThrows<CipherException>("byte $i bit $bit") { MasterKeyVault.unlockWithRecovery(tampered, created.recoveryCode) }
            }
        }
    }

    @Test
    fun malformedVaultsAreRejected() {
        val created = MasterKeyVault.create(password, fast)
        for (size in listOf(0, 5, created.vault.size - 1)) {
            assertThrows<CipherFormatException>("size $size") { MasterKeyVault.unlockWithPassword(created.vault.copyOf(size), password) }
        }
        assertThrows<CipherFormatException>("extra byte") { MasterKeyVault.unlockWithPassword(created.vault + byteArrayOf(0), password) }
        assertThrows<CipherFormatException>("file instead of vault") { MasterKeyVault.unlockWithPassword(ByteArray(created.vault.size), password) }
    }

    @Test
    fun hugeArgon2ParametersInVaultAreRejectedBeforeAllocation() {
        val created = MasterKeyVault.create(password, fast)
        val tampered = created.vault.clone()
        // memory field (u32 at offset 7) = 0xFFFFFFFF
        for (i in 7..10) tampered[i] = 0xFF.toByte()
        assertThrows<CipherFormatException>("huge memory") { MasterKeyVault.unlockWithPassword(tampered, password) }
    }

    @Test
    fun vaultMasterKeyWorksWithFileCipherAcrossPasswordChangeAndRecovery() {
        val created = MasterKeyVault.create(password, fast)
        val data = ByteArray(150_000) { (it % 251).toByte() }
        val encrypted = ByteArrayOutputStream().also {
            FileCipher.encrypt(created.masterKey, ByteArrayInputStream(data), it, FileMetadata("doc.pdf", data.size.toLong()))
        }.toByteArray()

        val changed = MasterKeyVault.changePassword(created.vault, password, "other".toByteArray(), fast)
        for (key in listOf(
            MasterKeyVault.unlockWithPassword(changed, "other".toByteArray()),
            MasterKeyVault.unlockWithRecovery(changed, created.recoveryCode),
        )) {
            val out = ByteArrayOutputStream()
            val metadata = FileCipher.decrypt(key, ByteArrayInputStream(encrypted), out)
            assertArrayEquals(data, out.toByteArray())
            assertEquals("doc.pdf", metadata.name)
        }
    }
}
