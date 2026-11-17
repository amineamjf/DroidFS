package sushi.hardcore.droidfs.cipher

import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** AES-256-GCM helpers shared by the file format and the master key vault. */
internal object Aead {
    fun encrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, data: ByteArray, offset: Int = 0, length: Int = data.size): ByteArray {
        return run(Cipher.ENCRYPT_MODE, key, nonce, aad, data, offset, length)
    }

    /** @throws CipherAuthException if the key is wrong or the data/aad were modified */
    fun decrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, data: ByteArray, offset: Int = 0, length: Int = data.size): ByteArray {
        try {
            return run(Cipher.DECRYPT_MODE, key, nonce, aad, data, offset, length)
        } catch (e: GeneralSecurityException) {
            throw CipherAuthException("Authentication failed: wrong key or corrupted data", e)
        }
    }

    private fun run(mode: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray, data: ByteArray, offset: Int, length: Int): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(CipherFormat.TAG_SIZE * 8, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(data, offset, length)
    }
}
