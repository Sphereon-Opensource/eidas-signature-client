package com.sphereon.vdx.ades.model

import com.sphereon.vdx.ades.Base64Serializer
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.enums.SignatureAlg
import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable

@Serializable
data class Signature(
    @Serializable(with = Base64Serializer::class)
    val value: ByteArray,
    val algorithm: SignatureAlg,
    val signMode: SignMode,
    val keyEntry: IKeyEntry,
    val providerId: String,
    val date: Instant
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Signature

        if (!value.contentEquals(other.value)) return false
        if (algorithm != other.algorithm) return false
        if (signMode != other.signMode) return false
        if (keyEntry != other.keyEntry) return false
        if (providerId != other.providerId) return false
        if (date != other.date) return false

        return true
    }

    override fun hashCode(): Int {
        var result = value.contentHashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + signMode.hashCode()
        result = 31 * result + keyEntry.hashCode()
        result = 31 * result + providerId.hashCode()
        result = 31 * result + date.hashCode()
        return result
    }
}
