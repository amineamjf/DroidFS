package sushi.hardcore.droidfs.cipher

import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import sushi.hardcore.droidfs.cipher.CipherFormat as F

/**
 * Local container (file "DFSK" v1) holding the 32-byte master key wrapped twice:
 *
 *  - a password slot: key = Argon2id(password, salt, params)
 *  - a recovery slot: key = HKDF-SHA256(recovery secret), the secret being shown once to the user
 *    as a [RecoveryCode]
 *
 * Either slot unlocks the same master key, so changing the password or using the recovery code
 * never changes the master key and never invalidates files already encrypted with [FileCipher].
 * Nothing in this class does any I/O or network access: the caller stores the vault bytes locally
 * and the master key and recovery code never leave the device.
 *
 * Layout: magic "DFSK" (4) | version (1) | slot count = 2 (1) | password slot (86) | recovery slot (61)
 *  - password slot: type 1 | memKiB u32 | iterations u32 | parallelism u8 | salt (16) | nonce (12) | wrapped key (48)
 *  - recovery slot: type 2 | nonce (12) | wrapped key (48)
 * The additional data of each wrap is every byte of the slot before its nonce, plus magic and version.
 */
object MasterKeyVault {
    private val MAGIC = "DFSK".toByteArray()
    private const val VERSION: Byte = 1
    private const val SLOT_PASSWORD: Byte = 1
    private const val SLOT_RECOVERY: Byte = 2
    private const val SALT_SIZE = 16
    private const val HEADER_SIZE = 6
    private const val PASSWORD_SLOT_SIZE = 1 + 4 + 4 + 1 + SALT_SIZE + F.NONCE_SIZE + F.WRAPPED_KEY_SIZE
    private const val RECOVERY_SLOT_SIZE = 1 + F.NONCE_SIZE + F.WRAPPED_KEY_SIZE
    private const val VAULT_SIZE = HEADER_SIZE + PASSWORD_SLOT_SIZE + RECOVERY_SLOT_SIZE
    private val HKDF_INFO = "DroidFS recovery wrap v1".toByteArray()

    private val random = SecureRandom()

    class Created(val vault: ByteArray, val masterKey: ByteArray, val recoveryCode: String)

    /** Generate a new random master key. The caller must show [Created.recoveryCode] to the user. */
    fun create(password: ByteArray, params: Argon2Params = Argon2Params.DEFAULT): Created {
        val masterKey = randomBytes(F.KEY_SIZE)
        val secret = randomBytes(RecoveryCode.SECRET_SIZE)
        try {
            val vault = assemble(passwordSlot(masterKey, password, params), recoverySlot(masterKey, secret))
            return Created(vault, masterKey, RecoveryCode.encode(secret))
        } finally {
            secret.fill(0)
        }
    }

    /** @throws CipherAuthException wrong password or modified vault */
    fun unlockWithPassword(vault: ByteArray, password: ByteArray): ByteArray {
        checkVault(vault)
        val buffer = ByteBuffer.wrap(vault, HEADER_SIZE, PASSWORD_SLOT_SIZE)
        val aadEnd = HEADER_SIZE + 1 + 4 + 4 + 1 + SALT_SIZE
        val params = readParams(buffer)
        val salt = ByteArray(SALT_SIZE).also { buffer.get(it) }
        val kek = Argon2idKdf.derive(password, salt, params)
        try {
            return unwrap(vault, kek, aadEnd)
        } finally {
            kek.fill(0)
        }
    }

    /**
     * @throws InvalidRecoveryCodeException the code is mistyped (checksum) or malformed
     * @throws CipherAuthException the code is well-formed but does not belong to this vault
     */
    fun unlockWithRecovery(vault: ByteArray, recoveryCode: String): ByteArray {
        checkVault(vault)
        val secret = RecoveryCode.decode(recoveryCode)
        val kek = recoveryKey(secret)
        try {
            return unwrap(vault, kek, HEADER_SIZE + PASSWORD_SLOT_SIZE + 1, HEADER_SIZE + PASSWORD_SLOT_SIZE)
        } finally {
            secret.fill(0)
            kek.fill(0)
        }
    }

    /** Re-wrap the same master key under a new password; the recovery code stays valid. */
    fun changePassword(vault: ByteArray, oldPassword: ByteArray, newPassword: ByteArray, params: Argon2Params = Argon2Params.DEFAULT): ByteArray {
        val masterKey = unlockWithPassword(vault, oldPassword)
        try {
            return assemble(passwordSlot(masterKey, newPassword, params), recoverySlotBytes(vault))
        } finally {
            masterKey.fill(0)
        }
    }

    /** Set a new password using the recovery code (forgotten password). The recovery code stays valid. */
    fun resetPasswordWithRecovery(vault: ByteArray, recoveryCode: String, newPassword: ByteArray, params: Argon2Params = Argon2Params.DEFAULT): ByteArray {
        val masterKey = unlockWithRecovery(vault, recoveryCode)
        try {
            return assemble(passwordSlot(masterKey, newPassword, params), recoverySlotBytes(vault))
        } finally {
            masterKey.fill(0)
        }
    }

    /** Replace the recovery code. The previous code stops working. Returns the new vault and the new code. */
    fun rotateRecovery(vault: ByteArray, password: ByteArray): Pair<ByteArray, String> {
        val masterKey = unlockWithPassword(vault, password)
        val secret = randomBytes(RecoveryCode.SECRET_SIZE)
        try {
            val newVault = assemble(passwordSlotBytes(vault), recoverySlot(masterKey, secret))
            return Pair(newVault, RecoveryCode.encode(secret))
        } finally {
            masterKey.fill(0)
            secret.fill(0)
        }
    }

    private fun passwordSlot(masterKey: ByteArray, password: ByteArray, params: Argon2Params): ByteArray {
        require(password.isNotEmpty()) { "Empty password" }
        val salt = randomBytes(SALT_SIZE)
        val slot = ByteBuffer.allocate(PASSWORD_SLOT_SIZE)
        slot.put(SLOT_PASSWORD)
        slot.putInt(params.memoryKiB)
        slot.putInt(params.iterations)
        slot.put(params.parallelism.toByte())
        slot.put(salt)
        val kek = Argon2idKdf.derive(password, salt, params)
        try {
            return finishSlot(slot, kek, masterKey)
        } finally {
            kek.fill(0)
        }
    }

    private fun recoverySlot(masterKey: ByteArray, secret: ByteArray): ByteArray {
        val slot = ByteBuffer.allocate(RECOVERY_SLOT_SIZE)
        slot.put(SLOT_RECOVERY)
        val kek = recoveryKey(secret)
        try {
            return finishSlot(slot, kek, masterKey)
        } finally {
            kek.fill(0)
        }
    }

    /** Append nonce and wrapped key to a slot whose parameter bytes were already written. */
    private fun finishSlot(slot: ByteBuffer, kek: ByteArray, masterKey: ByteArray): ByteArray {
        val aad = MAGIC + byteArrayOf(VERSION) + slot.array().copyOf(slot.position())
        val nonce = randomBytes(F.NONCE_SIZE)
        slot.put(nonce)
        slot.put(Aead.encrypt(kek, nonce, aad, masterKey))
        check(!slot.hasRemaining())
        return slot.array()
    }

    private fun assemble(passwordSlot: ByteArray, recoverySlot: ByteArray): ByteArray {
        return (MAGIC + byteArrayOf(VERSION, 2) + passwordSlot + recoverySlot).also { check(it.size == VAULT_SIZE) }
    }

    private fun passwordSlotBytes(vault: ByteArray) = vault.copyOfRange(HEADER_SIZE, HEADER_SIZE + PASSWORD_SLOT_SIZE)
    private fun recoverySlotBytes(vault: ByteArray) = vault.copyOfRange(HEADER_SIZE + PASSWORD_SLOT_SIZE, VAULT_SIZE)

    /**
     * Unwrap the key of the slot starting at [slotStart]; every byte of the slot before its nonce
     * (ending at [aadEnd]) plus magic and version is authenticated.
     */
    private fun unwrap(vault: ByteArray, kek: ByteArray, aadEnd: Int, slotStart: Int = HEADER_SIZE): ByteArray {
        val aad = MAGIC + byteArrayOf(VERSION) + vault.copyOfRange(slotStart, aadEnd)
        val nonce = vault.copyOfRange(aadEnd, aadEnd + F.NONCE_SIZE)
        return Aead.decrypt(kek, nonce, aad, vault, aadEnd + F.NONCE_SIZE, F.WRAPPED_KEY_SIZE)
    }

    private fun checkVault(vault: ByteArray) {
        if (vault.size != VAULT_SIZE) throw CipherFormatException("Invalid vault size")
        if (!vault.copyOfRange(0, 4).contentEquals(MAGIC)) throw CipherFormatException("Not a DFSK vault")
        if (vault[4] != VERSION) throw CipherFormatException("Unsupported vault version ${vault[4]}")
        if (vault[5].toInt() != 2) throw CipherFormatException("Invalid vault slot count")
        if (vault[HEADER_SIZE] != SLOT_PASSWORD || vault[HEADER_SIZE + PASSWORD_SLOT_SIZE] != SLOT_RECOVERY) {
            throw CipherFormatException("Invalid vault slots")
        }
    }

    private fun readParams(buffer: ByteBuffer): Argon2Params {
        buffer.get() // slot type
        val memory = buffer.getInt().toLong() and 0xFFFFFFFFL
        val iterations = buffer.getInt().toLong() and 0xFFFFFFFFL
        val parallelism = buffer.get().toLong() and 0xFF
        if (!Argon2Params.isValid(memory, iterations, parallelism)) {
            throw CipherFormatException("Invalid Argon2 parameters in vault")
        }
        return Argon2Params(memory.toInt(), iterations.toInt(), parallelism.toInt())
    }

    private fun recoveryKey(secret: ByteArray): ByteArray = hkdfSha256(secret, HKDF_INFO)

    /** HKDF-SHA256 (RFC 5869) with an empty salt, one output block (32 bytes). */
    internal fun hkdfSha256(ikm: ByteArray, info: ByteArray): ByteArray {
        val extract = Mac.getInstance("HmacSHA256")
        extract.init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
        val prk = extract.doFinal(ikm)
        try {
            val expand = Mac.getInstance("HmacSHA256")
            expand.init(SecretKeySpec(prk, "HmacSHA256"))
            expand.update(info)
            expand.update(1)
            return expand.doFinal()
        } finally {
            prk.fill(0)
        }
    }

    private fun randomBytes(size: Int) = ByteArray(size).also { random.nextBytes(it) }
}
