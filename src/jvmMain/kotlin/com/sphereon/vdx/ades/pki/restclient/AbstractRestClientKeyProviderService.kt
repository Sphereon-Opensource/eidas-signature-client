package com.sphereon.vdx.ades.pki.restclient

import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.model.KeyProviderSettings
import com.sphereon.vdx.ades.pki.AbstractKeyProviderService
import com.sphereon.vdx.ades.rest.client.ApiClient
import com.sphereon.vdx.ades.rest.client.auth.Authentication
import com.sphereon.vdx.ades.rest.client.auth.HttpBearerAuth
import com.sphereon.vdx.ades.rest.client.auth.OAuth

private const val BEARER_LITERAL = "bearer"
private const val OAUTH2_LITERAL = "oauth2"

abstract class AbstractRestClientKeyProviderService(
    settings: KeyProviderSettings,
    private val restClientConfig: RestClientConfig
) : AbstractKeyProviderService(settings) {

    protected val apiClient: ApiClient

    init {
        assertConfig()
        val authMap = initAuth()
        apiClient = newApiClient(authMap)

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

    private fun newApiClient(authMap: MutableMap<String, Authentication>): ApiClient {
        val apiClient = KotlinApiClient(authMap)

        apiClient.basePath = restClientConfig.baseUrl
        if (restClientConfig.connectTimeoutInMS != null) {
            apiClient.connectTimeout = restClientConfig.connectTimeoutInMS
        }
        if (restClientConfig.readTimeoutInMS != null) {
            apiClient.readTimeout = restClientConfig.readTimeoutInMS
        }
        restClientConfig.defaultHeaders?.forEach {
            apiClient.addDefaultHeader(it.key, it.value)
        }
        return apiClient
    }

    private fun initAuth(): MutableMap<String, Authentication> {
        val authMap = mutableMapOf<String, Authentication>()
        if (restClientConfig.oAuth2 != null) {
            val auth = OAuth(
                restClientConfig.baseUrl ?: throw SignClientException("Base url for the REST Signature service has not been set"),
                restClientConfig.oAuth2.tokenUrl
            )
            auth.setFlow(restClientConfig.oAuth2.flow)
            auth.setScope(restClientConfig.oAuth2.scope)
            auth.setCredentials(restClientConfig.oAuth2.clientId, restClientConfig.oAuth2.clientSecret, restClientConfig.oAuth2.debug)
            restClientConfig.oAuth2.accessToken?.let { auth.setAccessToken(it) }
            authMap[OAUTH2_LITERAL] = auth
        }
        if (restClientConfig.bearerAuth != null) {
            val auth = HttpBearerAuth(restClientConfig.bearerAuth.schema)
            auth.bearerToken = restClientConfig.bearerAuth.bearerToken
            authMap[BEARER_LITERAL] = auth
        }
        return authMap
    }

    private fun assertConfig() {
        if (restClientConfig.baseUrl == null) {
            throw SignClientException("Cannot create a REST certificate Service Provider without a base URL")
        }
    }
}
