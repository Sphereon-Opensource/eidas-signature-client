package com.sphereon.vdx.ades.model

import com.sphereon.vdx.ades.Base64Serializer
import com.sphereon.vdx.ades.enums.DigestAlg
import com.sphereon.vdx.ades.enums.SignMode

@kotlinx.serialization.Serializable
data class SignOutput(
    @kotlinx.serialization.Serializable(with = Base64Serializer::class)
    val value: ByteArray,
    val signMode: SignMode,
    val digestAlgorithm: DigestAlg,
    val name: String? = "document",
    val mimeType: String?,
    val signature: Signature
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SignOutput

        if (!value.contentEquals(other.value)) return false
        if (signMode != other.signMode) return false
        if (digestAlgorithm != other.digestAlgorithm) return false
        if (name != other.name) return false
        if (mimeType != other.mimeType) return false
        if (signature != other.signature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = value.contentHashCode()
        result = 31 * result + signMode.hashCode()
        result = 31 * result + digestAlgorithm.hashCode()
        result = 31 * result + (name?.hashCode() ?: 0)
        result = 31 * result + (mimeType?.hashCode() ?: 0)
        result = 31 * result + signature.hashCode()
        return result
    }
}
