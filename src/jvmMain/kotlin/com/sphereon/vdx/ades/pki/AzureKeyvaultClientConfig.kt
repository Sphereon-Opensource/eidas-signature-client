package com.sphereon.vdx.ades.pki

@kotlinx.serialization.Serializable
data class AzureKeyvaultClientConfig(
    val keyvaultUrl: String,
    val tenantId: String,
    val credentialOpts: CredentialOpts,
    val hsmType: HSMType,
    val applicationId: String? = null,
    val headers: List<Header>? = null,
    val exponentialBackoffRetryOpts: ExponentialBackoffRetryOpts? = null,
)

@kotlinx.serialization.Serializable
data class CredentialOpts(
    val credentialMode: CredentialMode,
    val secretCredentialOpts: SecretCredentialOpts? = null,
    val certificateCredentialOpts: CertificateCredentialOpts? = null,
    val interactiveBrowserCredentialOpts: InteractiveBrowserCredentialOpts? = null,
    val usernamePasswordCredentialOpts: UsernamePasswordCredentialOpts? = null
)

enum class CredentialMode(val credentialType: CredentialType) {
    SERVICE_CLIENT_SECRET(CredentialType.SERVICE),
    SERVICE_CLIENT_CERTIFICATE(CredentialType.SERVICE),
    USER_INTERACTIVE_BROWSER(CredentialType.USER),
    USER_USERNAME_PASSWORD(CredentialType.USER)
}

enum class CredentialType {
    SERVICE, USER
}

enum class HSMType {
    KEYVAULT, MANAGED_HSM
}

@kotlinx.serialization.Serializable
data class Header(
    val name: String,
    val values: List<String>? = mutableListOf()
)

private const val SECOND = 1000L
private const val ONE = 1
private const val FIFTEEN = 15

@kotlinx.serialization.Serializable
data class ExponentialBackoffRetryOpts(
    val maxRetries: Int? = 10,
    val baseDelayInMS: Long? = ONE * SECOND,
    val maxDelayInMS: Long? = FIFTEEN * SECOND
)

/**
 *  Authenticate with client secret.
 */
@kotlinx.serialization.Serializable
data class SecretCredentialOpts(
    val clientId: String,
    val clientSecret: String,
)

/**
 *  Authenticate with a client certificate.
 */
@kotlinx.serialization.Serializable
data class CertificateCredentialOpts(
    val clientId: String,
    val pemCertificatePath: String,
)

/**
 * Authenticate interactively in the browser.
 */
@kotlinx.serialization.Serializable
data class InteractiveBrowserCredentialOpts(
    val clientId: String,
    val redirectUrl: String
)

/**
 * Authenticate with username, password.
 */
@kotlinx.serialization.Serializable
data class UsernamePasswordCredentialOpts(
    val clientId: String,
    val userName: String,
    val password: String
)
