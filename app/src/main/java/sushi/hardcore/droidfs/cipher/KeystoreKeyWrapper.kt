package sushi.hardcore.droidfs.cipher

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import sushi.hardcore.droidfs.cipher.CipherFormat as F

/**
 * Wraps the master key with a non-exportable AES-256-GCM key stored in the Android Keystore.
 *
 * The wrapped blob is only useful on this device and this app install: it lets the app reopen the
 * master key without asking for the password every time, while the password and recovery slots of
 * [MasterKeyVault] remain the way to get it back after a reinstall or on another device.
 * Nothing leaves the device.
 *
 * Android Keystore AES keys exist from API 23; below that [isSupported] is false and the app must
 * rely on the password only. Blob layout: version (1) | IV (12) | wrapped key (32) + tag (16).
 */
@RequiresApi(Build.VERSION_CODES.M)
class KeystoreKeyWrapper(private val alias: String = DEFAULT_ALIAS) {
    companion object {
        const val DEFAULT_ALIAS = "droidfs_cipher_master_wrap"
        private const val PROVIDER = "AndroidKeyStore"
        private const val VERSION: Byte = 1
        private val AAD = "DroidFS keystore wrap v1".toByteArray()
        private const val BLOB_SIZE = 1 + F.NONCE_SIZE + F.KEY_SIZE + F.TAG_SIZE

        fun isSupported() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
    }

    fun hasKey(): Boolean = keyStore().containsAlias(alias)

    /** Remove the Keystore key. Previously returned blobs can no longer be unwrapped. */
    fun delete() {
        val ks = keyStore()
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }

    /** Wrap [masterKey], creating the Keystore key on first use. */
    fun wrap(masterKey: ByteArray): ByteArray {
        require(masterKey.size == F.KEY_SIZE) { "Master key must be ${F.KEY_SIZE} bytes" }
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            cipher.updateAAD(AAD)
            val ciphertext = cipher.doFinal(masterKey)
            val iv = cipher.iv
            if (iv.size != F.NONCE_SIZE) throw CipherException("Unexpected IV size from Keystore")
            return byteArrayOf(VERSION) + iv + ciphertext
        } catch (e: GeneralSecurityException) {
            throw CipherException("Keystore wrap failed", e)
        } catch (e: ProviderException) {
            throw CipherException("Keystore wrap failed", e)
        }
    }

    /**
     * @throws CipherFormatException the blob is not a wrapped key
     * @throws CipherAuthException the Keystore key is missing/changed or the blob was modified
     */
    fun unwrap(blob: ByteArray): ByteArray {
        if (blob.size != BLOB_SIZE || blob[0] != VERSION) throw CipherFormatException("Invalid Keystore blob")
        val key = loadKey() ?: throw CipherAuthException("Keystore key not found")
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(F.TAG_SIZE * 8, blob, 1, F.NONCE_SIZE))
            cipher.updateAAD(AAD)
            return cipher.doFinal(blob, 1 + F.NONCE_SIZE, blob.size - 1 - F.NONCE_SIZE)
        } catch (e: GeneralSecurityException) {
            throw CipherAuthException("Keystore unwrap failed", e)
        } catch (e: ProviderException) {
            throw CipherAuthException("Keystore unwrap failed", e)
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun loadKey(): SecretKey? = keyStore().getKey(alias, null) as? SecretKey

    private fun getOrCreateKey(): SecretKey {
        loadKey()?.let { return it }
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(spec)
        return generator.generateKey()
    }
}
