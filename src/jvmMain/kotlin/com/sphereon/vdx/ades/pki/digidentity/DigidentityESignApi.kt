package com.sphereon.vdx.ades.pki.digidentity

import com.fasterxml.jackson.annotation.JsonProperty
import com.sphereon.vdx.ades.rest.client.ApiClient
import com.sphereon.vdx.ades.rest.client.ApiException
import jakarta.ws.rs.core.GenericType

private const val TYPE_SIGN = "sign"
private const val CONTENT_TYPE_JSON = "application/vnd.api+json"
private const val AUTH_NAME_OAUTH2 = "oauth2"

class DigidentityESignApi(private val apiClient: ApiClient) {


    data class Data<T>(
        val id: String? = null, // Nullable for requests
        val type: String,
        val attributes: T
    )

    class SignRequestAttributes(
        @JsonProperty("hash_to_sign") val hashToSign: String
    )


    class SignRequest(hashToSign: String) {
        val data: Data<SignRequestAttributes> = Data(
            type = TYPE_SIGN,
            attributes = SignRequestAttributes(hashToSign = hashToSign)
        )
    }

    data class SignResponse(val data: Data<SignResponseAttributes>)

    data class SignResponseAttributes(
        val signature: String,
        val certificate: String,
        @JsonProperty("hash_to_sign") val hash_to_sign: String
    )

    data class SignResult(
        val kid: String,
        val signature: String,
        val certificate: String,
        val hashToSign: String
    )

    // Example of converting a response to a SignResult
    private fun signResultFrom(data: Data<SignResponseAttributes>): SignResult {
        return SignResult(
            kid = data.id ?: throw IllegalArgumentException("ID is missing in response"),
            signature = data.attributes.signature,
            certificate = data.attributes.certificate,
            hashToSign = data.attributes.hash_to_sign
        )
    }


    @Throws(ApiException::class)
    fun signHash(kid: String, hash: String): SignResult {
        val signRequest = SignRequest(hash)
        val localVarReturnType: GenericType<SignResponse> = object : GenericType<SignResponse>() {}
        val response = apiClient.invokeAPI(
            "sign",
            "/auto_signers/${kid}/sign",
            "POST",
            emptyList(),
            signRequest,
            emptyMap(),
            emptyMap(),
            emptyMap(),
            CONTENT_TYPE_JSON,
            CONTENT_TYPE_JSON,
            arrayOf(AUTH_NAME_OAUTH2),
            localVarReturnType,
            false
        )
        return signResultFrom(response.data.data)
    }
}
