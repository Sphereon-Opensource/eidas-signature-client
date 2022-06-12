package com.sphereon.vdx.ades.pki

import com.azure.core.http.policy.RetryOptions
import com.azure.core.http.policy.RetryPolicy
import com.azure.security.keyvault.certificates.CertificateAsyncClient
import com.azure.security.keyvault.certificates.CertificateClientBuilder
import com.azure.security.keyvault.certificates.CertificateServiceVersion
import com.azure.security.keyvault.keys.KeyAsyncClient
import com.azure.security.keyvault.keys.KeyClientBuilder
import com.azure.security.keyvault.keys.KeyServiceVersion
import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.SigningException
import com.sphereon.vdx.ades.enums.CertificateProviderType
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.sign.util.*
import java.util.*

private const val KEY_NAME_VERSION_SEP = ":"

open class AzureKeyvaultCertificateProviderService(
    settings: CertificateProviderSettings,
    val keyvaultConfig: AzureKeyvaultClientConfig
) : AbstractCertificateProviderService(settings) {

    private val keyClient: KeyAsyncClient
    private val certClient: CertificateAsyncClient?

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
            .buildAsyncClient()


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
                    .buildAsyncClient()
        }
    }

    override fun getKeys(): List<IKeyEntry> {
        val res = keyClient.listPropertiesOfKeys().filter { it.isEnabled }.map {
            getKey("${it.id}${KEY_NAME_VERSION_SEP}${it.version}")!!

        }
        return res.toIterable().toList()
    }

    override fun getKey(alias: String): IKeyEntry? {
        val cachedKey = cacheService.get(alias)
        if (cachedKey != null) {
            return cachedKey
        }
        val kvNames = aliasToKVKeyName(alias)
        val certificateVersion = certClient?.getCertificateVersion(kvNames.first, kvNames.second)
        val keyMono =
            certificateVersion?.map { it.toKeyEntry() } ?: keyClient.getKey(kvNames.first, kvNames.second).map { it.toKeyEntry() }

        // This is a workaround, since we can be called from a Web(Test)Client, and this library/method is not reactive. Using block() would result in an error
        // TODO: Make methods reactive and provide a sync client as well
        val key = keyMono.toFuture().get()
        cacheService.put(key)
        return key
    }

    override fun isValidSignature(signInput: SignInput, signature: Signature, publicKey: Key): Boolean {
        Objects.requireNonNull(signInput, "signInput cannot be null!")
        Objects.requireNonNull(signature, "Signature cannot be null!")
        Objects.requireNonNull(publicKey, "Public key cannot be null!")
        // Let's try using the public key first
        return super.isValidSignature(signInput, signature, publicKey) ||

                // In case we have a RAW digest we need Azure. Let's check for any digest type anyway though
                (ConnectionFactory.connection(
                    settings = settings,
                    alias = signature.keyEntry.alias,
                    keyvaultConfig = keyvaultConfig
                ) as AzureKeyvaultTokenConnection).isValidSignature(signInput, signature)
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

        return if (isDigestMode(signInput)) {
            tokenConnection.signDigest(signInput.toDigest(), mgf?.toDSS(), keyEntry.toDSS()).toRaw()
                .fromDSS(signMode = signInput.signMode, keyEntry, settings.id, signInput.signingDate)
        } else {
            tokenConnection.sign(signInput.toBeSigned(), signInput.digestAlgorithm.toDSS(), mgf?.toDSS(), keyEntry.toDSS())
                .fromDSS(signMode = signInput.signMode, keyEntry, settings.id, signInput.signingDate)
        }
    }


}
