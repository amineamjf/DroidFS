package sushi.hardcore.droidfs.cipher

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

/**
 * Argon2id cost parameters.
 *
 * @param memoryKiB memory cost in KiB
 * @param iterations number of passes
 * @param parallelism number of lanes
 */
data class Argon2Params(val memoryKiB: Int, val iterations: Int, val parallelism: Int) {
    init {
        require(isValid(memoryKiB.toLong(), iterations.toLong(), parallelism.toLong())) { "Invalid Argon2 parameters" }
    }

    companion object {
        /** 64 MiB, 3 passes, 2 lanes: a reasonable cost for a phone. */
        val DEFAULT = Argon2Params(64 * 1024, 3, 2)

        const val MAX_MEMORY_KIB = 1024 * 1024L
        const val MAX_ITERATIONS = 20L
        const val MAX_PARALLELISM = 16L

        /** Bounds also protect against absurd values read from a tampered vault. */
        fun isValid(memoryKiB: Long, iterations: Long, parallelism: Long): Boolean {
            return parallelism in 1..MAX_PARALLELISM &&
                iterations in 1..MAX_ITERATIONS &&
                memoryKiB in (8 * parallelism)..MAX_MEMORY_KIB
        }
    }
}

object Argon2idKdf {
    /** Derive [length] bytes from [password] and [salt] (Argon2id, version 1.3). */
    fun derive(password: ByteArray, salt: ByteArray, params: Argon2Params, length: Int = CipherFormat.KEY_SIZE): ByteArray {
        require(salt.size >= 8) { "Salt too short" }
        val argon2Params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withMemoryAsKB(params.memoryKiB)
            .withIterations(params.iterations)
            .withParallelism(params.parallelism)
            .build()
        val generator = Argon2BytesGenerator()
        generator.init(argon2Params)
        val output = ByteArray(length)
        generator.generateBytes(password, output)
        return output
    }
}
