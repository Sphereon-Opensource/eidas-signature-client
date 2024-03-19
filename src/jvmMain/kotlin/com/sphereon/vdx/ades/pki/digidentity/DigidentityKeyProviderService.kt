package com.sphereon.vdx.ades.pki.digidentity

import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.enums.KeyProviderType
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.enums.SignatureAlg
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.KeyProviderSettings
import com.sphereon.vdx.ades.model.SignInput
import com.sphereon.vdx.ades.model.Signature
import com.sphereon.vdx.ades.pki.restclient.AbstractRestClientKeyProviderService
import com.sphereon.vdx.ades.pki.restclient.OAuth2Config
import com.sphereon.vdx.ades.pki.restclient.RestClientConfig
import com.sphereon.vdx.ades.sign.util.CertificateUtil
import com.sphereon.vdx.ades.sign.util.isActive
import com.sphereon.vdx.ades.sign.util.toDSS
import com.sphereon.vdx.ades.sign.util.toDigest
import eu.europa.esig.dss.spi.DSSUtils
import mu.KotlinLogging

private const val API_KEY_HEADER = "Api-Key"

private val logger = KotlinLogging.logger {}

private const val DUMMY_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

private val CLEANUP_REGEX = "[\\r\\n\\t]+".toRegex()

@OptIn(ExperimentalStdlibApi::class)
open class DigidentityKeyProviderService(
    settings: KeyProviderSettings,
    val providerConfig: DigidentityProviderConfig,
) : AbstractRestClientKeyProviderService(settings, restClientConfigFrom(providerConfig)) {

    private var esignApi: DigidentityESignApi

    init {
        assertSettings()
        esignApi = DigidentityESignApi(apiClient)
    }


    override fun createSignatureImpl(signInput: SignInput, keyEntry: IKeyEntry, mgf: MaskGenFunction?): Signature {
        logger.entry(signInput, keyEntry, mgf)
        logger.info { "Creating signature with date '${signInput.signingDate}' provider Id '${settings.id}', key Id '${keyEntry.kid}' and sign input '${signInput.name}'..." }

        val isDigest = isDigestMode(signInput)
        val digest = if (isDigest) {
            val digest = signInput.toDigest().hexValue
            if (digest.length != 64) {
                throw IllegalArgumentException("Invalid hash supplied to be signed")
            }
            digest.lowercase() // Digidentity API crashes when we send uppercase hex chars
        } else {
            DSSUtils.digest(signInput.digestAlgorithm!!.toDSS(), signInput.input).toHexString()
        }
        val signResponse = esignApi.signHash(keyEntry.kid, digest)
        val signatureClean = signResponse.signature.replace(CLEANUP_REGEX, "")

        val signature = Signature(
            value = java.util.Base64.getDecoder().decode(signatureClean),
            algorithm = SignatureAlg.RSA_SHA256, // The only supported algo atm
            signMode = signInput.signMode,
            keyEntry = keyEntry,
            providerId = signResponse.kid,
            date = signInput.signingDate
        )
        logger.info { "Signature created with date '${signInput.signingDate}' provider Id '${settings.id}', key Id '${keyEntry.kid}' and sign input '${signInput.name}'" }
        logger.exit(signature)
        return signature
    }

    override fun getKeys(): List<IKeyEntry> {
        throw PKIException("Retrieving multiple certificates using the Digidenity client is not possible currently")
    }

    override fun getKey(kid: String): IKeyEntry? {
        logger.entry(kid)
        try {
            val cachedKey = cacheService.get(kid)
            if (cachedKey != null && cachedKey.certificate?.isActive() == true) {
                logger.debug { "Cache hit for key entry with id $kid" }
                return cachedKey
            }
            logger.debug { "Cache miss for key entry with id $kid" }

            // Dummy sign action to fetch certificate
            val signResponse = esignApi.signHash(kid, DUMMY_HASH)
            val certData = signResponse.certificate.toByteArray()
            val x509Certificate = CertificateUtil.toX509Certificate(certData)
            val keyEntry = CertificateUtil.toKeyEntry(x509Certificate, signResponse.kid)
            cacheService.put(kid, keyEntry)
            return keyEntry
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
                tokenUrl = it.tokenUrl,
                clientId = it.clientId,
                clientSecret = it.clientSecret,
            ),
            defaultHeaders = mapOf(Pair(API_KEY_HEADER, it.apiKey))
        )
    }
        ?: throw SignClientException("Cannot create a Digidentity Provider; secretCredentialOpts is empty and the only credentialMode currently supported is SERVICE_CLIENT_SECRET which requires secretCredentialOpts")
}
