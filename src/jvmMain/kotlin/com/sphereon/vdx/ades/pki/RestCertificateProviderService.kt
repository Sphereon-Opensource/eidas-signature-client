package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.RestClientConfig
import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.enums.CertificateProviderType
import com.sphereon.vdx.ades.enums.CryptoAlg
import com.sphereon.vdx.ades.model.CertificateProviderSettings
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.KeyEntry
import com.sphereon.vdx.ades.rest.client.ApiClient
import com.sphereon.vdx.ades.rest.client.api.CertificatesApi
import com.sphereon.vdx.ades.rest.client.auth.HttpBearerAuth
import com.sphereon.vdx.ades.rest.client.auth.OAuth
import com.sphereon.vdx.ades.sign.util.CertificateUtil
import com.sphereon.vdx.ades.sign.util.toCertificate


private const val BEARER_LITERAL = "bearer"
private const val OAUTH2_LITERAL = "oauth2"

open class RestCertificateProviderService(override val settings: CertificateProviderSettings, val restClientConfig: RestClientConfig) :
    ICertificateProviderService {

    private val cacheService = CacheService(settings)

    private val apiClient: ApiClient

    init {
        assertRestSettings()
        apiClient = newApiClient()
        initAuth()
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
        val certResponse = certApi.getCertificateWithHttpInfo(alias)
        if (certResponse.statusCode == 404) {
            return null
        }
        val certData = certResponse.data

        val key = KeyEntry(
            alias = alias,
            certificate = CertificateUtil.toX509Certificate(certData.certificate).toCertificate(),
            certificateChain = certData.certificateChain?.map {
                CertificateUtil.toX509Certificate(it).toCertificate()
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
        if (restClientConfig.bearerToken != null) {
            val auth = HttpBearerAuth(restClientConfig.bearerToken.schema)
            auth.bearerToken = restClientConfig.bearerToken.bearerToken
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
