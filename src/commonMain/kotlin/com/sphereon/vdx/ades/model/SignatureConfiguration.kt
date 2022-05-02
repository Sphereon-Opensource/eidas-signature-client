package com.sphereon.vdx.ades.model

data class SignatureConfiguration(
//    val id: String,
    val signatureParameters: SignatureParameters,
    val timestampParameters: TimestampParameterSettings? = null
)
