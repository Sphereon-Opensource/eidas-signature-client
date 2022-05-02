package com.sphereon.vdx.ades.model

@kotlinx.serialization.Serializable
data class CertificateProviderSettings(
    val id: String,
    val config: CertificateProviderConfig,
    val passwordInputCallback: PasswordInputCallback? = null
)
