package com.sphereon.vdx.ades.sign

import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.enums.DigestAlg
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.pki.IKeyProviderService
import com.sphereon.vdx.ades.pki.RestClientConfig
import com.sphereon.vdx.ades.rest.client.ApiClient
import com.sphereon.vdx.ades.rest.client.api.SigningApi
import com.sphereon.vdx.ades.rest.client.auth.HttpBearerAuth
import com.sphereon.vdx.ades.rest.client.auth.OAuth
import com.sphereon.vdx.ades.rest.client.model.ConfigKeyBinding
import com.sphereon.vdx.ades.rest.client.model.DetermineSignInput
import com.sphereon.vdx.ades.rest.client.model.Digest
import com.sphereon.vdx.ades.rest.client.model.DigestAlgorithm
import kotlinx.datetime.Instant

private const val BEARER_LITERAL = "bearer"
private const val OAUTH2_LITERAL = "oauth2"

open class RestSignatureProviderService(
    override val keyProvider: IKeyProviderService,
    val restClientConfig: RestClientConfig
) : AbstractSignatureProviderService() {
    private val apiClient: ApiClient
    private val delegate = KeySignatureService(keyProvider)

    init {
        apiClient = newApiClient()
        initAuth()
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
                restClientConfig.baseUrl
                    ?: throw SignClientException("Base url for the REST Signature service has not been set"),
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

    private fun newSigningApi(): SigningApi {
        return SigningApi(apiClient)
    }

    override fun determineSignInputImpl(
        origData: OrigData,
        kid: String,
        signMode: SignMode,
        signatureConfiguration: SignatureConfiguration
    ): SignInput {
        val signInputResponse = newSigningApi().determineSignInput(
            DetermineSignInput()
                .origData(com.sphereon.vdx.ades.rest.client.model.OrigData()
                    .name(origData.name)
                    .content(origData.value)
                    .mimeType(origData.mimeType))
                .signMode(com.sphereon.vdx.ades.rest.client.model.SignMode.valueOf(signMode.name))
                .binding(
                    ConfigKeyBinding()
                    .kid(kid)
                    .keyProviderId(keyProvider.settings.id)
                )
        )

        return SignInput(
            input = signInputResponse.signInput.input,
            signMode = SignMode.valueOf(signInputResponse.signInput.signMode.name),
            signingDate = Instant.fromEpochSeconds(signInputResponse.signInput.signingDate.epochSecond),
            digestAlgorithm = DigestAlg.valueOf(signInputResponse.signInput.digestAlgorithm.name),
            name = signInputResponse.signInput.name,
            binding = ConfigKeyBinding(
                kid = signInputResponse.signInput.binding.kid,
                signatureConfigId = signInputResponse.signInput.binding.signatureConfigId,
                keyProviderId = signInputResponse.signInput.binding.keyProviderId
            )
        )
    }

    override fun digestImpl(signInput: SignInput): SignInput {
        val digest = newSigningApi().digest(
            Digest().signInput(
                com.sphereon.vdx.ades.rest.client.model.SignInput()
                    .name(signInput.name)
                    .input(signInput.input)
                    .signMode(com.sphereon.vdx.ades.rest.client.model.SignMode.valueOf(signInput.signMode.name))
                    .digestAlgorithm(signInput.digestAlgorithm?.name?.let { DigestAlgorithm.valueOf(it) })
                    .signingDate(java.time.Instant.ofEpochSecond(signInput.signingDate.epochSeconds))
                    .binding(ConfigKeyBinding()
                        .kid(signInput.binding.kid)
                        .signatureConfigId(signInput.binding.signatureConfigId)
                        .keyProviderId(signInput.binding.keyProviderId)
                    )
            )
        )

        return SignInput( // TODO refactor both returns to fun
            input = digest.signInput.input,
            signMode = SignMode.valueOf(digest.signInput.signMode.name),
            signingDate = Instant.fromEpochSeconds(digest.signInput.signingDate.epochSecond),
            digestAlgorithm = DigestAlg.valueOf(digest.signInput.digestAlgorithm.name),
            name = digest.signInput.name,
            binding = ConfigKeyBinding(
                kid = digest.signInput.binding.kid,
                signatureConfigId = digest.signInput.binding.signatureConfigId,
                keyProviderId = digest.signInput.binding.keyProviderId
            )
        )
    }

    override fun signImpl(
        origData: OrigData,
        kid: String,
        signMode: SignMode,
        signatureConfiguration: SignatureConfiguration
    ): SignOutput {
        val keyEntry = keyProvider.getKey(kid) ?: throw PKIException("Could not retrieve key entry for kid $kid")
        return delegate.sign(origData, keyEntry, signMode, signatureConfiguration)
    }

    override fun signImpl(
        origData: OrigData,
        signature: Signature,
        signatureConfiguration: SignatureConfiguration
    ): SignOutput {
        return delegate.sign(origData, signature, signatureConfiguration)
    }

}
