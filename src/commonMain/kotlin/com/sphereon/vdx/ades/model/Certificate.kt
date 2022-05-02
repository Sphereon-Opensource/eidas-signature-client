package com.sphereon.vdx.ades.model

import com.sphereon.vdx.ades.Base64Serializer

@kotlinx.serialization.Serializable
class Certificate(@kotlinx.serialization.Serializable(with = Base64Serializer::class) val value: ByteArray)
