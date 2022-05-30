package com.sphereon.vdx.ades.model

import com.sphereon.vdx.ades.Base64Serializer
import kotlinx.datetime.Instant

@kotlinx.serialization.Serializable
class Certificate(
    @kotlinx.serialization.Serializable(with = Base64Serializer::class) val value: ByteArray,
    val fingerPrint: String,
    val serialNumber: String? = null,
    val issuerDN: String,
    val subjectDN: String,
    val notBefore: Instant,
    val notAfter: Instant,
    val keyUsage: Map<String, Boolean>? = null
)
