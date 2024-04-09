package com.sphereon.vdx.ades.pki.digidentity

import com.sphereon.vdx.ades.pki.azure.CredentialType

@kotlinx.serialization.Serializable
data class DigidentityProviderConfig(
    val baseUrl: String,
    val autoSignerId: String?,
    val credentialOpts: DigidentityCredentialOpts
)

@kotlinx.serialization.Serializable
data class DigidentityCredentialOpts(
    val credentialMode: DigidentityCredentialMode,
    val secretCredentialOpts: DigidentitySecretCredentialOpts? = null,
)

/**
 *  Authenticate with client secret & API key.
 */
@kotlinx.serialization.Serializable
data class DigidentitySecretCredentialOpts(
    val clientId: String,
    val clientSecret: String,
    val apiKey: String,
    val tokenUrl: String = "https://auth.digidentity-preproduction.eu/oauth2/token.json"
)

enum class DigidentityCredentialMode(val credentialType: CredentialType) {
    SERVICE_CLIENT_SECRET(CredentialType.SERVICE),
}
