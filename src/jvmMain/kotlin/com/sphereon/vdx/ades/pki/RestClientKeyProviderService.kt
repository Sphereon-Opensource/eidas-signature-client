package com.sphereon.vdx.ades.pki

import AbstractCacheObjectSerializer
import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.enums.CryptoAlg
import com.sphereon.vdx.ades.enums.KeyProviderType
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.enums.SignatureAlg
import com.sphereon.vdx.ades.model.KeyProviderSettings
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.SignInput
import com.sphereon.vdx.ades.model.Signature
import com.sphereon.vdx.ades.model.KeyEntry
import com.sphereon.vdx.ades.rest.client.ApiClient
import com.sphereon.vdx.ades.rest.client.api.KeysApi
import com.sphereon.vdx.ades.rest.client.api.SigningApi
import com.sphereon.vdx.ades.rest.client.auth.HttpBearerAuth
import com.sphereon.vdx.ades.rest.client.auth.OAuth
import com.sphereon.vdx.ades.rest.client.model.ConfigKeyBinding
import com.sphereon.vdx.ades.rest.client.model.CreateSignature
import com.sphereon.vdx.ades.rest.client.model.DigestAlgorithm
import com.sphereon.vdx.ades.rest.client.model.SignMode
import com.sphereon.vdx.ades.sign.util.CertificateUtil
import com.sphereon.vdx.ades.sign.util.toCertificate
import com.sphereon.vdx.ades.sign.util.toKey
import org.apache.http.HttpStatus

private const val BEARER_LITERAL = "bearer"
private const val OAUTH2_LITERAL = "oauth2"

open class RestClientKeyProviderService(
    settings: KeyProviderSettings,
    val restClientConfig: RestClientConfig,
    cacheObjectSerializer: AbstractCacheObjectSerializer<String, IKeyEntry>? = null
) :
    AbstractKeyProviderService(settings, cacheObjectSerializer) {

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
                .signInput(
                    com.sphereon.vdx.ades.rest.client.model.SignInput()
                        .name(signInput.name)
                        .input(signInput.input)
                        .signMode(SignMode.valueOf(signInput.signMode.name))
                        .digestAlgorithm(signInput.digestAlgorithm?.name?.let { DigestAlgorithm.valueOf(it) })
                        .signingDate(java.time.Instant.ofEpochSecond(signInput.signingDate.epochSeconds))
                        .binding(ConfigKeyBinding()
                            .kid(keyEntry.kid)
                            .keyProviderId(settings.id)
                        )
                )
        )
        return Signature(
            value = java.util.Base64.getDecoder().decode(signature.signature.value),
            algorithm = SignatureAlg.valueOf(signature.signature.algorithm.name),
            signMode = signInput.signMode,
            keyEntry = keyEntry,
            providerId = signature.signature.binding.keyProviderId,
            date = signInput.signingDate
        )
    }

    override fun getKeys(): List<IKeyEntry> {
        throw PKIException("Retrieving multiple certificates using the REST client is not possible currently")
    }

    override fun getKey(kid: String): IKeyEntry? {
        val cachedKey = cacheService.get(kid)
        if (cachedKey != null) {
            return cachedKey
        }

        val certApi = newKeysApi()
        val certResponse = certApi.getKeyWithHttpInfo(settings.id, kid)
        if (certResponse.statusCode == HttpStatus.SC_NOT_FOUND) {
            return null
        }
        val certData = certResponse.data

        val x509Certificate = CertificateUtil.toX509Certificate(certData.keyEntry.certificate.value)
        val key = KeyEntry(
            kid = kid,
            publicKey = x509Certificate.publicKey.toKey(),
            certificate = x509Certificate.toCertificate(),
            certificateChain = certData.keyEntry.certificateChain?.map {
                CertificateUtil.toX509Certificate(it.value).toCertificate()
            },
            encryptionAlgorithm = CryptoAlg.valueOf(certData.keyEntry.encryptionAlgorithm.value)
        )

        cacheService.put(kid, key)
        return key
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

    fun newKeysApi(): KeysApi {
        return KeysApi(apiClient)
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
        if (settings.config.type != KeyProviderType.REST) {
            throw SignClientException(
                "Cannot create a REST certificate Service Provider without mode set to REST. Current mode: ${settings.config.type}"
            )
        }
        /*if (restClientConfig == null) {
            throw SignClientException("Cannot create a REST certificate Service Provider without a REST config")
        }*/
        if (restClientConfig.baseUrl == null) {
            throw SignClientException("Cannot create a REST certificate Service Provider without a base URL")
        }
    }
}
