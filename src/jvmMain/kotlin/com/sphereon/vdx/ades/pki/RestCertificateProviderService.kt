package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.enums.CertificateProviderType
import com.sphereon.vdx.ades.enums.CryptoAlg
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.enums.SignatureAlg
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.rest.client.ApiClient
import com.sphereon.vdx.ades.rest.client.api.CertificatesApi
import com.sphereon.vdx.ades.rest.client.api.SigningApi
import com.sphereon.vdx.ades.rest.client.auth.HttpBearerAuth
import com.sphereon.vdx.ades.rest.client.auth.OAuth
import com.sphereon.vdx.ades.rest.client.model.ConfigCertificateBinding
import com.sphereon.vdx.ades.rest.client.model.CreateSignature
import com.sphereon.vdx.ades.rest.client.model.DigestAlgorithm
import com.sphereon.vdx.ades.rest.client.model.SignMode
import com.sphereon.vdx.ades.sign.util.CertificateUtil
import com.sphereon.vdx.ades.sign.util.toCertificate
import com.sphereon.vdx.ades.sign.util.toKey


private const val BEARER_LITERAL = "bearer"
private const val OAUTH2_LITERAL = "oauth2"

open class RestCertificateProviderService(settings: CertificateProviderSettings, val restClientConfig: RestClientConfig) :
    AbstractCertificateProviderService(settings) {

    private val apiClient: ApiClient

    init {
        assertRestSettings()
        apiClient = newApiClient()
        initAuth()
    }

    override fun createSignatureImpl(signInput: SignInput, keyEntry: IKeyEntry, mgf: MaskGenFunction?): Signature {
        val signingClient = newSigningApi()
        val signature = signingClient.createSignature(
            CreateSignature()
                .binding(
                    ConfigCertificateBinding()
                        .certificateProviderId(settings.id)
                        .certificateAlias(keyEntry.alias)
                        .signatureConfigId(null)
                )
                .signInput(
                    com.sphereon.vdx.ades.rest.client.model.SignInput()
                        .signMode(SignMode.valueOf(signInput.signMode.name))
                        .input(java.util.Base64.getEncoder().encodeToString(signInput.input))
                        .name(signInput.name)
                        .digestAlgorithm(signInput.digestAlgorithm?.name?.let { DigestAlgorithm.valueOf(it) })
                )
        )
        return Signature(
            value = java.util.Base64.getDecoder().decode(signature.signature.value),
            algorithm = SignatureAlg.valueOf(signature.signature.algorithm.name),
            signMode = signInput.signMode,
            keyEntry = keyEntry,
            providerId = signature.signature.binding.certificateProviderId,
            date = signInput.signingDate
        )
    }

    override fun getKeys(): List<IKeyEntry> {
        throw PKIException("Retrieving multiple certificates using the REST client is not possible currently")
    }

    override fun getKey(alias: String): IKeyEntry? {
        val cachedKey = cacheService.get(alias)
        if (cachedKey != null) {
            return cachedKey
        }

        val certApi = newCertApi()
        val certResponse = certApi.getKeyWithHttpInfo(settings.id, alias)
        if (certResponse.statusCode == 404) {
            return null
        }
        val certData = certResponse.data

        val x509Certificate = CertificateUtil.toX509Certificate(certData.keyEntry.certificate.value)
        val key = KeyEntry(
            alias = alias,
            publicKey = x509Certificate.publicKey.toKey(),
            certificate = x509Certificate.toCertificate(),
            certificateChain = certData.keyEntry.certificateChain?.map {
                CertificateUtil.toX509Certificate(it.value).toCertificate()
            },
            // fixme: Needs to come from response
            encryptionAlgorithm = CryptoAlg.RSA
        )

        cacheService.put(key)
        return key
    }

    fun oAuth(): OAuth {
        return if (apiClient.authentications.containsKey(OAUTH2_LITERAL)) apiClient.getAuthentication(OAUTH2_LITERAL) as OAuth else throw SignClientException(
            "OAuth2 authentication not configured for REST client"
        )
    }

    fun bearerAuth(): HttpBearerAuth {
        return if (apiClient.authentications.containsKey(BEARER_LITERAL)) apiClient.getAuthentication(BEARER_LITERAL) as HttpBearerAuth else throw SignClientException(
            "Bearer auth not configured for REST client"
        )
    }

    fun newCertApi(): CertificatesApi {
        return CertificatesApi(apiClient)
    }

    fun newSigningApi(): SigningApi {
        return SigningApi(apiClient)
    }

    private fun newApiClient(): ApiClient {
        val apiClient = ApiClient()

        apiClient.basePath = restClientConfig.baseUrl
        if (restClientConfig.connectTimeoutInMS != null) {
            apiClient.connectTimeout = restClientConfig.connectTimeoutInMS
        }
        if (restClientConfig.readTimeoutInMS != null) {
            apiClient.readTimeout = restClientConfig.readTimeoutInMS
        }
        return apiClient
    }

    private fun initAuth() {
        if (restClientConfig.oAuth2 != null) {
            val auth = OAuth(
                restClientConfig.baseUrl ?: throw SignClientException("Base url for the REST Signature service has not been set"),
                restClientConfig.oAuth2.tokenUrl
            )
            auth.setFlow(restClientConfig.oAuth2.flow)
            auth.setScope(restClientConfig.oAuth2.scope)
            auth.setCredentials(restClientConfig.oAuth2.clientId, restClientConfig.oAuth2.clientSecret, restClientConfig.oAuth2.debug)
            auth.setAccessToken(restClientConfig.oAuth2.accessToken)
            apiClient.authentications[OAUTH2_LITERAL] = auth
        }
        if (restClientConfig.bearerAuth != null) {
            val auth = HttpBearerAuth(restClientConfig.bearerAuth.schema)
            auth.bearerToken = restClientConfig.bearerAuth.bearerToken
            apiClient.authentications[BEARER_LITERAL] = auth
        }
    }

    private fun assertRestSettings() {
        if (settings.config.type != CertificateProviderType.REST) {
            throw SignClientException("Cannot create a REST certificate Service Provider without mode set to REST. Current mode: ${settings.config.type}")
        }
        if (restClientConfig == null) {
            throw SignClientException("Cannot create a REST certificate Service Provider without a REST config")
        }
        if (restClientConfig.baseUrl == null) {
            throw SignClientException("Cannot create a REST certificate Service Provider without a base URL")
        }
    }
}
