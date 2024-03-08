package com.sphereon.vdx.ades.pki.digidentity

import AbstractCacheObjectSerializer
import com.azure.identity.implementation.util.CertificateUtil
import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.enums.KeyProviderType
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.KeyProviderSettings
import com.sphereon.vdx.ades.model.SignInput
import com.sphereon.vdx.ades.model.Signature
import com.sphereon.vdx.ades.pki.AbstractRestClientKeyProviderService
import com.sphereon.vdx.ades.pki.OAuth2Config
import com.sphereon.vdx.ades.pki.RestClientConfig
import mu.KotlinLogging

private const val API_KEY_HEADER = "Api-Key"

private val logger = KotlinLogging.logger {}

open class DigidentityKeyProviderService(
    settings: KeyProviderSettings,
    val providerConfig: DigidentityProviderConfig,
    cacheObjectSerializer: AbstractCacheObjectSerializer<String, IKeyEntry>? = null
) : AbstractRestClientKeyProviderService(settings, restClientConfigFrom(providerConfig), cacheObjectSerializer) {

    private var esignApi: DigidentityESignApi

    init {
        assertSettings()
        esignApi = DigidentityESignApi(apiClient)
    }

    override fun createSignatureImpl(signInput: SignInput, keyEntry: IKeyEntry, mgf: MaskGenFunction?): Signature {
        TODO("Not yet implemented")
    }

    override fun getKeys(): List<IKeyEntry> {
        TODO("Not yet implemented")
    }

    override fun getKey(kid: String): IKeyEntry? {
        logger.entry(kid)
        try {
            val cachedKey = cacheService.get(kid)
            if (cachedKey != null) {
                // TODO check if certificate expired, otherwise we will have to expel to from the cache
                logger.debug { "Cache hit for key entry with id $kid" }
                return cachedKey
            }
            logger.debug { "Cache miss for key entry with id $kid" }

            // Dummy sign action to fetch certificate
            val signResponse = esignApi.signHash(kid, "0000000000000000000000000000000000000000000000000000000000000000")
            val cert = CertificateUtil.publicKeyFromPem(signResponse.certificate.toByteArray())
            println(cert)
            return null
        } finally {
            logger.exit(kid)
        }
    }

    private fun assertSettings() {
        if (settings.config.type != KeyProviderType.DIGIDENTITY) {
            throw SignClientException("Cannot create a Digidentity Provider without mode set to DIGIDENTITY. Supplied mode: ${settings.config.type}")
        }
    }
}


fun restClientConfigFrom(providerConfig: DigidentityProviderConfig): RestClientConfig {
    val credentialOpts = providerConfig.credentialOpts
    if (credentialOpts.credentialMode != DigidentityCredentialMode.SERVICE_CLIENT_SECRET) {
        throw SignClientException("Cannot create a Digidentity Provider; only credentialMode currently supported is SERVICE_CLIENT_SECRET. Supplied mode: ${credentialOpts.credentialMode}")
    }

    return credentialOpts.secretCredentialOpts?.let {
        return RestClientConfig(
            baseUrl = providerConfig.baseUrl,
            oAuth2 = OAuth2Config(
                clientId = it.clientId,
                clientSecret = it.clientSecret,
            ),
            defaultHeaders = mapOf(Pair(API_KEY_HEADER, it.apiKey))
        )
    }
        ?: throw SignClientException("Cannot create a Digidentity Provider; secretCredentialOpts is empty and the only credentialMode currently supported is SERVICE_CLIENT_SECRET which requires secretCredentialOpts")
}
