package com.sphereon.vdx.ades.model

import com.sphereon.vdx.ades.Base64Serializer
import com.sphereon.vdx.ades.enums.DigestAlg
import com.sphereon.vdx.ades.enums.SignMode
import kotlinx.datetime.Instant

@kotlinx.serialization.Serializable
data class SignInput(
    @kotlinx.serialization.Serializable(with = Base64Serializer::class) val input: ByteArray,
    val signMode: SignMode,
    val signingDate: Instant,
    val digestAlgorithm: DigestAlg?,
    val name: String? = "document",
    val binding: ConfigKeyBinding
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SignInput

        if (!input.contentEquals(other.input)) return false
        if (signMode != other.signMode) return false
        if (signingDate != other.signingDate) return false
        if (digestAlgorithm != other.digestAlgorithm) return false
        if (name != other.name) return false
        if (binding != other.binding) return false

        return true
    }

    override fun hashCode(): Int {
        var result = input.contentHashCode()
        result = 31 * result + signMode.hashCode()
        result = 31 * result + signingDate.hashCode()
        result = 31 * result + (digestAlgorithm?.hashCode() ?: 0)
        result = 31 * result + (name?.hashCode() ?: 0)
        result = 31 * result + (binding.hashCode() ?: 0)
        return result
    }
}
