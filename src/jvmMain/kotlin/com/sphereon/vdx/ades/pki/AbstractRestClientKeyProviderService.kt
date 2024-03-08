package com.sphereon.vdx.ades.pki

import AbstractCacheObjectSerializer
import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.KeyProviderSettings
import com.sphereon.vdx.ades.rest.client.ApiClient
import com.sphereon.vdx.ades.rest.client.auth.HttpBearerAuth
import com.sphereon.vdx.ades.rest.client.auth.OAuth

private const val BEARER_LITERAL = "bearer"
private const val OAUTH2_LITERAL = "oauth2"

abstract class AbstractRestClientKeyProviderService(
    settings: KeyProviderSettings,
    private val restClientConfig: RestClientConfig,
    cacheObjectSerializer: AbstractCacheObjectSerializer<String, IKeyEntry>?
) : AbstractKeyProviderService(settings, cacheObjectSerializer) {

    protected val apiClient: ApiClient

    init {
        assertConfig()
        apiClient = newApiClient()
        initAuth()
    }

    fun oAuth(): OAuth {
        return if (apiClient.authentications.containsKey(OAUTH2_LITERAL)) apiClient.getAuthentication(OAUTH2_LITERAL) as OAuth
        else throw SignClientException(
            "OAuth2 authentication not configured for REST client"
        )
    }

    fun bearerAuth(): HttpBearerAuth {
        return if (apiClient.authentications.containsKey(BEARER_LITERAL)) apiClient.getAuthentication(BEARER_LITERAL) as HttpBearerAuth
        else throw SignClientException(
            "Bearer auth not configured for REST client"
        )
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
        restClientConfig.defaultHeaders?.forEach {
            apiClient.addDefaultHeader(it.key, it.value)
        }
    }

    private fun assertConfig() {
        if (restClientConfig.baseUrl == null) {
            throw SignClientException("Cannot create a REST certificate Service Provider without a base URL")
        }
    }
}
