package com.sphereon.vdx.ades.pki

import AbstractCacheObjectSerializer
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
import com.sphereon.vdx.ades.enums.KeyProviderType
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.sign.util.*
import mu.KotlinLogging
import java.util.*

private const val KEY_NAME_VERSION_SEP = ":"

private val logger = KotlinLogging.logger {}

open class AzureKeyvaultKeyProviderService(
    settings: KeyProviderSettings,
    val keyvaultConfig: AzureKeyvaultClientConfig,
    cacheObjectSerializer: AbstractCacheObjectSerializer<String, IKeyEntry>? = null
) : AbstractKeyProviderService(settings, cacheObjectSerializer) {

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
            HSMType.MANAGED_HSM -> {
                logger.warn { "Azure keyvault key provider ${settings.id} in mode: Managed HSM. This mode as opposed to 'keyvault' mode is untested currently!" }
                null
            }
            HSMType.KEYVAULT -> {
                logger.debug { "Azure keyvault key provider ${settings.id} in mode: Keyvault. Creating a certificate client." }
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
    }

    override fun getKeys(): List<IKeyEntry> {
        val res = keyClient.listPropertiesOfKeys().filter { it.isEnabled }.map {
            getKey("${it.id}${KEY_NAME_VERSION_SEP}${it.version}")!!

        }
        return res.toIterable().toList()
    }

    override fun getKey(kid: String): IKeyEntry? {
        logger.exit(kid)
        val cachedKey = cacheService.get(kid)
        if (cachedKey != null) {
            logger.debug { "Cache hit for key entry with id $kid" }
            return cachedKey
        }
        logger.debug { "Cache miss for key entry with id $kid" }
        val kvNames = kidToKVKeyName(kid)
        val certificateVersion = certClient?.getCertificateVersion(kvNames.first, kvNames.second)
        val keyMono =
            certificateVersion?.map { it.toKeyEntry() } ?: keyClient.getKey(kvNames.first, kvNames.second).map { it.toKeyEntry() }

        // This is a workaround, since we can be called from a Web(Test)Client, and this library/method is not reactive. Using block() would result in an error
        // TODO: Make methods reactive and provide a sync client as well
        val key = keyMono.toFuture().get()
        cacheService.put(key.kid, key)
        logger.exit(key)
        return key
    }

    override fun isValidSignature(signInput: SignInput, signature: Signature, publicKey: Key): Boolean {
        Objects.requireNonNull(signInput, "signInput cannot be null!")
        Objects.requireNonNull(signature, "Signature cannot be null!")
        Objects.requireNonNull(publicKey, "Public key cannot be null!")
        // Let's try using the public key first
        var valid = super.isValidSignature(signInput, signature, publicKey)

        if (!valid) {
            logger.info { "RAW digest signature found. Calling Azure Keyvault to do an online check" }
            // In case we have a RAW digest we need Azure. Let's check for any digest type anyway though
            valid = (ConnectionFactory.connection(
                settings = settings,
                kid = signature.keyEntry.kid,
                keyvaultConfig = keyvaultConfig
            ) as AzureKeyvaultTokenConnection).isValidSignature(signInput, signature)
            logger.info {
                "Signature with date '${signature.date}' and provider '${signature.providerId}' for input '${signInput.name}' was ${if (valid) "VALID" else "INVALID"} according to Keyvault"
            }
        }
        return valid
    }

    private fun kidToKVKeyName(kid: String): Pair<String, String> {
        val pair = kid.split(KEY_NAME_VERSION_SEP).let { Pair(it[0], it.getOrNull(1) ?: "") }
        if (pair.second.lowercase() == "latest") {
            return pair.copy(second = "")
        }
        return pair
    }


    private fun assertKeyvaultSettings() {
        if (settings.config.type != KeyProviderType.AZURE_KEYVAULT) {
            throw SignClientException("Cannot create a Keyvault certificate Service Provider without mode set to Azure Keyvault. Current mode: ${settings.config.type}")
        }
    }


    override fun createSignatureImpl(signInput: SignInput, keyEntry: IKeyEntry, mgf: MaskGenFunction?): Signature {
        logger.entry(signInput, keyEntry, mgf)
        if (signInput.digestAlgorithm == null) throw SigningException("Digest algorithm needs to be specified at this point")

        val tokenConnection = ConnectionFactory.connection(settings = settings, kid = keyEntry.kid, keyvaultConfig = keyvaultConfig)

        val isDigest = isDigestMode(signInput)
        logger.info { "Creating signature with date '${signInput.signingDate}' provider Id '${settings.id}', key Id '${keyEntry.kid}' and sign input '${signInput.name}'..." }
        val signature = if (isDigest) {
            tokenConnection.signDigest(signInput.toDigest(), mgf?.toDSS(), keyEntry.toDSS()).toRaw()
                .fromDSS(signMode = signInput.signMode, keyEntry, settings.id, signInput.signingDate)
        } else {
            tokenConnection.sign(signInput.toBeSigned(), signInput.digestAlgorithm.toDSS(), mgf?.toDSS(), keyEntry.toDSS())
                .fromDSS(signMode = signInput.signMode, keyEntry, settings.id, signInput.signingDate)
        }
        logger.info { "Signature created with date '${signInput.signingDate}' provider Id '${settings.id}', key Id '${keyEntry.kid}' and sign input '${signInput.name}'" }
        logger.exit(signature)
        return signature
    }


}
