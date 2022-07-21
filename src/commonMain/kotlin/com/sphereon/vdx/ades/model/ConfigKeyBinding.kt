package com.sphereon.vdx.ades.model

@kotlinx.serialization.Serializable
data class ConfigKeyBinding(
    val kid: String,
    val signatureConfigId: String? = null,
    val keyProviderId: String
)
