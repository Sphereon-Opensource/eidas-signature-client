package com.sphereon.vdx.ades.pki

import com.azure.core.credential.TokenCredential
import com.azure.core.http.policy.ExponentialBackoffOptions
import com.azure.core.util.ClientOptions
import com.azure.core.util.Header
import com.azure.identity.*
import com.azure.security.keyvault.certificates.models.KeyVaultCertificate
import com.azure.security.keyvault.keys.models.KeyVaultKey
import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.enums.CryptoAlg
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.KeyEntry
import com.sphereon.vdx.ades.sign.util.CertificateUtil
import com.sphereon.vdx.ades.sign.util.toCertificate
import com.sphereon.vdx.ades.sign.util.toKey
import com.sphereon.vdx.ades.sign.util.toPublicKey
import java.security.cert.X509Certificate
import java.time.Duration

fun AzureKeyvaultClientConfig.toClientOptions(): ClientOptions? {
    if ((headers == null || headers.isEmpty()) && applicationId == null) {
        return null
    }
    return ClientOptions().setApplicationId(applicationId).setHeaders(headers?.map { Header(it.name, it.values) })
}

fun ExponentialBackoffRetryOpts.toExponentialBackoffOptions(): ExponentialBackoffOptions {
    return ExponentialBackoffOptions()
        .setMaxRetries(maxRetries)
        .setBaseDelay(if (baseDelayInMS == null) null else Duration.ofMillis(baseDelayInMS))
        .setMaxDelay(if (maxDelayInMS == null) null else Duration.ofMillis(maxDelayInMS))
}

fun CredentialOpts.toTokenCredential(tenantId: String): TokenCredential {
    return when (credentialMode) {
        CredentialMode.SERVICE_CLIENT_SECRET -> secretCredentialOpts?.toClientSecretCredential(tenantId)
            ?: throw SignClientException("No client secret options provided")
        CredentialMode.SERVICE_CLIENT_CERTIFICATE -> certificateCredentialOpts?.toClientCertificateCredential(tenantId)
            ?: throw SignClientException("No client certificate options provided")
        CredentialMode.USER_INTERACTIVE_BROWSER -> interactiveBrowserCredentialOpts?.toInteractiveBrowserCredential(tenantId)
            ?: throw SignClientException("No interactive browser options provided")
        CredentialMode.USER_USERNAME_PASSWORD -> usernamePasswordCredentialOpts?.toUsernamePasswordCredential(tenantId)
            ?: throw SignClientException("No username password options provided")
    }
}

private fun SecretCredentialOpts.toClientSecretCredential(tenantId: String): ClientSecretCredential {
    return ClientSecretCredentialBuilder()
        .clientId(clientId)
        .clientSecret(clientSecret)
        .tenantId(tenantId)
        .build()
}

private fun CertificateCredentialOpts.toClientCertificateCredential(tenantId: String): ClientCertificateCredential {
    return ClientCertificateCredentialBuilder()
        .clientId(clientId)
        .pemCertificate(pemCertificatePath)
        .tenantId(tenantId)
        .build()
}

private fun UsernamePasswordCredentialOpts.toUsernamePasswordCredential(tenantId: String): UsernamePasswordCredential {
    return UsernamePasswordCredentialBuilder()
        .clientId(clientId)
        .username(userName)
        .password(password)
        .tenantId(tenantId)
        .build()
}

private fun InteractiveBrowserCredentialOpts.toInteractiveBrowserCredential(tenantId: String): InteractiveBrowserCredential {
    return InteractiveBrowserCredentialBuilder()
        .clientId(clientId)
        .redirectUrl(redirectUrl)
        .tenantId(tenantId)
        .build()
}


fun KeyVaultCertificate.toKeyEntry(): IKeyEntry {
    val x509Certificate = CertificateUtil.toX509Certificate(cer)
    val x509Chain: MutableList<X509Certificate> = mutableListOf()// mutableListOf(/*x509Certificate*/)
    x509Chain.addAll(CertificateUtil.downloadExtraCertificates(x509Certificate))
    x509Chain.add(x509Certificate)

    return KeyEntry(
        alias = "${properties.name}:${properties.version}",
        encryptionAlgorithm = if (x509Certificate.sigAlgName.endsWith("RSA")) CryptoAlg.RSA else CryptoAlg.valueOf(x509Certificate.publicKey.algorithm),
        certificate = x509Certificate.toCertificate(),
        publicKey = x509Certificate.toPublicKey(),
        certificateChain = x509Chain?.map { it.toCertificate() }
    )
}

fun KeyVaultKey.toKeyEntry(): IKeyEntry {

    // TODO: Certificate in case of keyvault (not managed hsm)
    val keyUsage: Map<String, Boolean>? = CertificateUtil.keyUsage(key.keyOps.map { it.toString() })
/*    val cert = Certificate(
        keyUsage = keyUsage,
        notBefore = properties.notBefore.toInstant().toKotlinInstant(),
        notAfter = properties.expiresOn.toInstant().toKotlinInstant(),
        subjectDN = this.key.
    )*/
    return KeyEntry(
        alias = "${properties.name}:${properties.version}",
        encryptionAlgorithm = CryptoAlg.valueOf(keyType.toString().replace("-HSM", "")),
        publicKey = this.key.toRsa().public.toKey()
    )
}
