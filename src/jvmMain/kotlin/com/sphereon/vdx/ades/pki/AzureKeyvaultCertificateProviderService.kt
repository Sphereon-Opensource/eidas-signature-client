package com.sphereon.vdx.ades.pki

import com.azure.core.http.policy.RetryOptions
import com.azure.core.http.policy.RetryPolicy
import com.azure.security.keyvault.certificates.CertificateClient
import com.azure.security.keyvault.certificates.CertificateClientBuilder
import com.azure.security.keyvault.certificates.CertificateServiceVersion
import com.azure.security.keyvault.keys.KeyClient
import com.azure.security.keyvault.keys.KeyClientBuilder
import com.azure.security.keyvault.keys.KeyServiceVersion
import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.SigningException
import com.sphereon.vdx.ades.enums.*
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.sign.util.*

private const val KEY_NAME_VERSION_SEP = ":"

open class AzureKeyvaultCertificateProviderService(
    settings: CertificateProviderSettings,
    val keyvaultConfig: AzureKeyvaultClientConfig
) : AbstractCertificateProviderService(settings) {

    private val keyClient: KeyClient
    private val certClient: CertificateClient?

    private val hasCerts: Boolean

    init {
        assertKeyvaultSettings()
        keyClient = KeyClientBuilder()
            .serviceVersion(KeyServiceVersion.V7_3)
            .vaultUrl(keyvaultConfig.keyvaultUrl)
            .clientOptions(keyvaultConfig.toClientOptions())
            .retryPolicy(
                if (keyvaultConfig.exponentialBackoffRetryOpts == null) null
                else RetryPolicy(RetryOptions(keyvaultConfig.exponentialBackoffRetryOpts.toExponentialBackoffOptions()))
            )
            .credential(keyvaultConfig.credentialOpts.toTokenCredential(keyvaultConfig.tenantId))
            .buildClient()


        // Azure Managed HSM has no Certs API
        hasCerts = keyvaultConfig.hsmType == HSMType.KEYVAULT
        certClient = when (keyvaultConfig.hsmType) {
            HSMType.MANAGED_HSM -> null
            HSMType.KEYVAULT ->
                CertificateClientBuilder()
                    .serviceVersion(CertificateServiceVersion.V7_3)
                    .vaultUrl(keyvaultConfig.keyvaultUrl)
                    .clientOptions(keyvaultConfig.toClientOptions())
                    .retryPolicy(
                        if (keyvaultConfig.exponentialBackoffRetryOpts == null) null
                        else RetryPolicy(RetryOptions(keyvaultConfig.exponentialBackoffRetryOpts.toExponentialBackoffOptions()))
                    )
                    .credential(keyvaultConfig.credentialOpts.toTokenCredential(keyvaultConfig.tenantId))
                    .buildClient()
        }
    }

    override fun getKeys(): List<IKeyEntry> {
        return keyClient.listPropertiesOfKeys().filter { it.isEnabled }.map {
            getKey("${it.id}${KEY_NAME_VERSION_SEP}${it.version}")!!
        }
    }

    override fun getKey(alias: String): IKeyEntry? {
        val cachedKey = cacheService.get(alias)
        if (cachedKey != null) {
            return cachedKey
        }
        val kvNames = aliasToKVKeyName(alias)
        val key = certClient?.getCertificateVersion(kvNames.first, kvNames.second)?.toKeyEntry() ?: keyClient.getKey(kvNames.first, kvNames.second)
            .toKeyEntry()

        cacheService.put(key)
        return key
    }

    private fun aliasToKVKeyName(alias: String): Pair<String, String> {
        var pair = alias.split(KEY_NAME_VERSION_SEP).let { Pair(it[0], it.getOrNull(1) ?: "") }
        if (pair.second.lowercase() == "latest") {
            return pair.copy(second = "")
        }
        return pair
    }


    private fun assertKeyvaultSettings() {
        if (settings.config.type != CertificateProviderType.AZURE_KEYVAULT) {
            throw SignClientException("Cannot create a Keyvault certificate Service Provider without mode set to Azure Keyvault. Current mode: ${settings.config.type}")
        }
    }


    override fun createSignatureImpl(signInput: SignInput, keyEntry: IKeyEntry, mgf: MaskGenFunction?): Signature {
        if (signInput.digestAlgorithm == null) throw SigningException("Digest algorithm needs to be specified at this point")

        val tokenConnection = ConnectionFactory.connection(settings = settings, alias = keyEntry.alias, keyvaultConfig = keyvaultConfig)

        return if (signInput.signMode == SignMode.DIGEST && signInput.digestAlgorithm != DigestAlg.NONE) {
            tokenConnection.signDigest(signInput.toDigest(), mgf?.toDSS(), keyEntry.toDSS()).fromDSS(signMode = signInput.signMode, keyEntry)
        } else {
            tokenConnection.sign(signInput.toBeSigned(), signInput.digestAlgorithm.toDSS(), mgf?.toDSS(), keyEntry.toDSS())
                .fromDSS(signMode = signInput.signMode, keyEntry)
        }
    }
}
