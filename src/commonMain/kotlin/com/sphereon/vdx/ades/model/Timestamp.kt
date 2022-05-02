package com.sphereon.vdx.ades.model

import com.sphereon.vdx.ades.Base64Serializer
import com.sphereon.vdx.ades.enums.TimestampType

@kotlinx.serialization.Serializable
class Timestamp(
    /** The timestamp token's DER-encoded binaries  */
    @kotlinx.serialization.Serializable(with = Base64Serializer::class)
    private val binaries: ByteArray,

    /** The canonicalization method (for XAdES/JAdES formats)  */
    private val canonicalizationMethod: String? = null,

    /** The type of the timestamp  */
    private val type: TimestampType? = null

    /** Defines signed references for a XAdES IndividualDataObjectsTimeStamp  */
//    private val includes: List<TimestampIncludeDTO>? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Timestamp

        if (!binaries.contentEquals(other.binaries)) return false
        if (canonicalizationMethod != other.canonicalizationMethod) return false
        if (type != other.type) return false

        return true
    }

    override fun hashCode(): Int {
        var result = binaries.contentHashCode()
        result = 31 * result + (canonicalizationMethod?.hashCode() ?: 0)
        result = 31 * result + (type?.hashCode() ?: 0)
        return result
    }
}
