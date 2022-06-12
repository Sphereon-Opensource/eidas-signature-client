package com.sphereon.vdx.ades.model

@kotlinx.serialization.Serializable
data class KeyProviderSettings(
    val id: String,
    val config: KeyProviderConfig,
    val passwordInputCallback: PasswordInputCallback? = null
)
