package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.rest.client.auth.OAuthFlow

@kotlinx.serialization.Serializable
data class RestClientConfig(
    val baseUrl: String? = "http://localhost/",
    val connectTimeoutInMS: Int? = 5000,
    val readTimeoutInMS: Int? = 10000,
    val oAuth2: OAuth2Config? = null,
    val bearerToken: BearerTokenConfig? = null
)

@kotlinx.serialization.Serializable
data class OAuth2Config(
    val tokenUrl: String = "https://auth-test.sphereon.com/auth/realms/sign-test/protocol/openid-connect/token",

    val flow: OAuthFlow? = OAuthFlow.APPLICATION,
    val scope: String? = null,
    val clientId: String? = null,
    val clientSecret: String? = null,
    val accessToken: String? = null,
    val debug: Boolean? = false

)

@kotlinx.serialization.Serializable
data class BearerTokenConfig(
    val schema: String? = "bearer",
    val bearerToken: String? = null
)
