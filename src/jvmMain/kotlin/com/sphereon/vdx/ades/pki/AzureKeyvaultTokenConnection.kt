package com.sphereon.vdx.ades.pki

import com.azure.core.http.policy.RetryOptions
import com.azure.core.http.policy.RetryPolicy
import com.azure.security.keyvault.keys.cryptography.CryptographyClient
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder
import com.azure.security.keyvault.keys.cryptography.CryptographyServiceVersion
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.model.Key
import com.sphereon.vdx.ades.model.SignInput
import com.sphereon.vdx.ades.model.Signature
import com.sphereon.vdx.ades.sign.AbstractSignatureTokenConnection
import com.sphereon.vdx.ades.sign.util.toDSS
import eu.europa.esig.dss.token.DSSPrivateKeyEntry
import java.security.GeneralSecurityException
import java.security.spec.AlgorithmParameterSpec

class AzureKeyvaultTokenConnection(keyvaultConfig: AzureKeyvaultClientConfig, alias: String) : AbstractSignatureTokenConnection() {
    val cryptoClient: CryptographyClient

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
        var javaAlg: eu.europa.esig.dss.enumerations.SignatureAlgorithm? = null

        val azureAlgorithm = if (javaSignatureAlgorithm.lowercase().endsWith("es256k")) {
            SignatureAlgorithm.ES256K
        } else {
            javaAlg = eu.europa.esig.dss.enumerations.SignatureAlgorithm.forJAVA(javaSignatureAlgorithm)
            javaAlg.toAzureSignatureAlgorithm()
        }

        return if (javaAlg == null || javaAlg.digestAlgorithm == null) {
            cryptoClient.sign(azureAlgorithm, bytes).signature
        } else {
            cryptoClient.signData(azureAlgorithm, bytes).signature
        }
    }

    fun isValidSignature(signInput: SignInput, signature: Signature): Boolean {
        return if (signInput.signMode == SignMode.DIGEST) {
            cryptoClient.verify(signature.algorithm.toDSS().toAzureSignatureAlgorithm(), signInput.input, signature.value).isValid
        } else {
            cryptoClient.verifyData(signature.algorithm.toDSS().toAzureSignatureAlgorithm(), signInput.input, signature.value).isValid
        }
    }

}
