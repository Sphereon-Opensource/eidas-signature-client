package com.sphereon.vdx.ades.pki

import AbstractCacheObjectSerializer
import com.sphereon.vdx.ades.Base64Serializer
import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.enums.DigestAlg
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.enums.SignatureAlg
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.rest.client.ApiClient
import com.sphereon.vdx.ades.rest.client.api.SigningApi
import com.sphereon.vdx.ades.rest.client.auth.HttpBearerAuth
import com.sphereon.vdx.ades.rest.client.auth.OAuth
import com.sphereon.vdx.ades.rest.client.model.ConfigKeyBinding
import com.sphereon.vdx.ades.rest.client.model.DetermineSignInput
import com.sphereon.vdx.ades.rest.client.model.Digest
import com.sphereon.vdx.ades.rest.client.model.DigestAlgorithm
import com.sphereon.vdx.ades.sign.IKidSignatureService
import kotlinx.datetime.Instant

private const val BEARER_LITERAL = "bearer"
private const val OAUTH2_LITERAL = "oauth2"

open class RestSignatureProviderService(
    settings: KeyProviderSettings,
    val restClientConfig: RestClientConfig,
    override val keyProvider: IKeyProviderService
) :
    AbstractSignatureProviderService() { //    AbstractSignatureProviderService() {

    private val apiClient: ApiClient

    init {
        //assertRestSettings()
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

    fun newSigningApi(): SigningApi {
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
                .binding(ConfigKeyBinding()
                    .kid(kid)
                    //.keyProviderId(settings.id) // TODO fix
                    )
                //.signatureFormParametersOverride(signatureConfiguration.signatureParameters) // TODO fix

        )

        return SignInput(
            input = signInputResponse.signInput.input,
            signMode = SignMode.valueOf(signInputResponse.signInput.signMode.name),
            signingDate = Instant.fromEpochSeconds(signInputResponse.signInput.signingDate.epochSecond),
            digestAlgorithm = DigestAlg.valueOf(signInputResponse.signInput.digestAlgorithm.name),
            name = signInputResponse.signInput.name,
        )

//        @kotlinx.serialization.Serializable(with = Base64Serializer::class) val input: ByteArray,
//        val signMode: SignMode,
//        val signingDate: Instant,
//        val digestAlgorithm: DigestAlg?,
//        val name: String? = "document"
    }

    override fun digestImpl(signInput: SignInput): SignInput { // TODO how do i get a kid here for the signInput binding?
        val digest = newSigningApi().digest(
            Digest().signInput(
                com.sphereon.vdx.ades.rest.client.model.SignInput()
                    .name(signInput.name)
                    .input(signInput.input)
                    .signMode(com.sphereon.vdx.ades.rest.client.model.SignMode.valueOf(signInput.signMode.name))
                    .digestAlgorithm(signInput.digestAlgorithm?.name?.let { DigestAlgorithm.valueOf(it) })
                    .signingDate(java.time.Instant.ofEpochSecond(signInput.signingDate.epochSeconds))
//                    .binding(ConfigKeyBinding()
//                        .kid(keyEntry.kid)
//                        .keyProviderId(settings.id)
//                    )
            )
        )

        return SignInput(
            input = digest.signInput.input,
            signMode = SignMode.valueOf(digest.signInput.signMode.name),
            signingDate = Instant.fromEpochSeconds(digest.signInput.signingDate.epochSecond),
            digestAlgorithm = DigestAlg.valueOf(digest.signInput.digestAlgorithm.name),
            name = digest.signInput.name,
        )
    }

    override fun signImpl(
        origData: OrigData,
        kid: String,
        signMode: SignMode,
        signatureConfiguration: SignatureConfiguration
    ): SignOutput {
        TODO("Not yet implemented")
    }

    override fun signImpl(
        origData: OrigData,
        signature: Signature,
        signatureConfiguration: SignatureConfiguration
    ): SignOutput {
        TODO("Not yet implemented")
    }

}
