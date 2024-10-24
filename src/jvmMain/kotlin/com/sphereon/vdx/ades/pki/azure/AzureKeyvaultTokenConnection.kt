package com.sphereon.vdx.ades.pki.azure

import com.azure.core.http.policy.RetryOptions
import com.azure.core.http.policy.RetryPolicy
import com.azure.security.keyvault.keys.cryptography.CryptographyAsyncClient
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder
import com.azure.security.keyvault.keys.cryptography.CryptographyServiceVersion
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.model.SignInput
import com.sphereon.vdx.ades.model.Signature
import com.sphereon.vdx.ades.pki.toAzureSignatureAlgorithm
import com.sphereon.vdx.ades.pki.toClientOptions
import com.sphereon.vdx.ades.pki.toExponentialBackoffOptions
import com.sphereon.vdx.ades.pki.toTokenCredential
import com.sphereon.vdx.ades.sign.AbstractSignatureTokenConnection
import com.sphereon.vdx.ades.sign.util.toDSS
import eu.europa.esig.dss.token.DSSPrivateKeyEntry
import mu.KotlinLogging
import java.security.GeneralSecurityException
import java.security.spec.AlgorithmParameterSpec

private val logger = KotlinLogging.logger {}

class AzureKeyvaultTokenConnection(keyvaultConfig: AzureKeyvaultClientConfig, kid: String) : AbstractSignatureTokenConnection() {
    private val cryptoClient: CryptographyAsyncClient

    init {
        val parts = kid.split(":")
        cryptoClient = CryptographyClientBuilder()
            .serviceVersion(CryptographyServiceVersion.V7_3)
            .clientOptions(keyvaultConfig.toClientOptions())
            .retryPolicy(
                if (keyvaultConfig.exponentialBackoffRetryOpts == null) null
                else RetryPolicy(RetryOptions(keyvaultConfig.exponentialBackoffRetryOpts.toExponentialBackoffOptions()))
            )
            .credential(keyvaultConfig.credentialOpts.toTokenCredential(keyvaultConfig.tenantId))
            .keyIdentifier("${keyvaultConfig.keyvaultUrl}keys/${parts[0]}/${parts.getOrNull(1) ?: ""}")
            .buildAsyncClient()
        logger.debug { "Azure keyvault connection for Key with id $kid and url ${keyvaultConfig.keyvaultUrl} created" }

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
            // This is a workaround, since we can be called from a Web(Test)Client, and this library/method is not reactive. Using block() would result in an error
            // TODO: Make methods reactive and provide a sync client as well
            cryptoClient.sign(azureAlgorithm, bytes).toFuture().get().signature
        } else {
            // This is a workaround, since we can be called from a Web(Test)Client, and this library/method is not reactive. Using block() would result in an error
            // TODO: Make methods reactive and provide a sync client as well
            cryptoClient.signData(azureAlgorithm, bytes).toFuture().get().signature
        }
    }

    fun isValidSignature(signInput: SignInput, signature: Signature): Boolean {
        return if (signInput.signMode == SignMode.DIGEST) {
            // This is a workaround, since we can be called from a Web(Test)Client, and this library/method is not reactive. Using block() would result in an error
            // TODO: Make methods reactive and provide a sync client as well
            cryptoClient.verify(signature.algorithm.toDSS().toAzureSignatureAlgorithm(), signInput.input, signature.value)
                .toFuture().get().isValid
        } else {
            // This is a workaround, since we can be called from a Web(Test)Client, and this library/method is not reactive. Using block() would result in an error
            // TODO: Make methods reactive and provide a sync client as well
            cryptoClient.verifyData(signature.algorithm.toDSS().toAzureSignatureAlgorithm(), signInput.input, signature.value)
                .toFuture().get().isValid
        }
    }

}
