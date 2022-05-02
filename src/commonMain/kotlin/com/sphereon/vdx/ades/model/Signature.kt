package com.sphereon.vdx.ades.model

import com.sphereon.vdx.ades.Base64Serializer
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.enums.SignatureAlg
import kotlinx.serialization.Serializable

@Serializable
data class Signature(
    @kotlinx.serialization.Serializable(with = Base64Serializer::class) val value: ByteArray,
    val algorithm: SignatureAlg,
    val signMode: SignMode,
    val certificate: Certificate?,
    val certificateChain: List<Certificate>?
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Signature

        if (!value.contentEquals(other.value)) return false
        if (algorithm != other.algorithm) return false
        if (certificate != other.certificate) return false
        if (certificateChain != other.certificateChain) return false

        return true
    }

    override fun hashCode(): Int {
        var result = value.contentHashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + (certificate?.hashCode() ?: 0)
        result = 31 * result + (certificateChain?.hashCode() ?: 0)
        return result
    }
}
