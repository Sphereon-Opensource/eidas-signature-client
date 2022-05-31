package com.sphereon.vdx.ades.pki

import com.azure.core.http.policy.RetryOptions
import com.azure.core.http.policy.RetryPolicy
import com.azure.security.keyvault.keys.cryptography.CryptographyClient
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder
import com.azure.security.keyvault.keys.cryptography.CryptographyServiceVersion
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm
import com.sphereon.vdx.ades.sign.AbstractSignatureTokenConnection
import eu.europa.esig.dss.token.DSSPrivateKeyEntry
import java.security.GeneralSecurityException
import java.security.spec.AlgorithmParameterSpec

class AzureKeyvaultTokenConnection(private val keyvaultConfig: AzureKeyvaultClientConfig, alias: String) : AbstractSignatureTokenConnection() {
    private val cryptoClient: CryptographyClient

    init {
        val parts = alias.split(":")
        cryptoClient = CryptographyClientBuilder()
            .serviceVersion(CryptographyServiceVersion.V7_3)
            .clientOptions(keyvaultConfig.toClientOptions())
            .retryPolicy(
                if (keyvaultConfig.exponentialBackoffRetryOpts == null) null
                else RetryPolicy(RetryOptions(keyvaultConfig.exponentialBackoffRetryOpts.toExponentialBackoffOptions()))
            )
            .credential(keyvaultConfig.credentialOpts.toTokenCredential(keyvaultConfig.tenantId))
            .keyIdentifier("${keyvaultConfig.keyvaultUrl}keys/${parts[0]}/${parts.getOrNull(1) ?: ""}")
            .buildClient()
    }

    override fun close() {
        // nothing todo
    }

    override fun getKeys(): MutableList<DSSPrivateKeyEntry> {
        throw NotImplementedError("getKeys not implemented for Azure Token Connections")
    }

    @Throws(GeneralSecurityException::class)
    override fun sign(
        bytes: ByteArray, javaSignatureAlgorithm: String, param: AlgorithmParameterSpec?,
        keyEntry: DSSPrivateKeyEntry
    ): ByteArray {
        return cryptoClient.sign(SignatureAlgorithm.RS256, bytes).signature
    }
}
