package com.sphereon.vdx.ades.pki

import AbstractCacheObjectSerializer
import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.enums.CryptoAlg
import com.sphereon.vdx.ades.enums.KeyProviderType
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.enums.SignatureAlg
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.rest.client.api.KeysApi
import com.sphereon.vdx.ades.rest.client.api.SigningApi
import com.sphereon.vdx.ades.rest.client.model.ConfigKeyBinding
import com.sphereon.vdx.ades.rest.client.model.CreateSignature
import com.sphereon.vdx.ades.rest.client.model.DigestAlgorithm
import com.sphereon.vdx.ades.rest.client.model.SignMode
import com.sphereon.vdx.ades.sign.util.CertificateUtil
import com.sphereon.vdx.ades.sign.util.toCertificate
import com.sphereon.vdx.ades.sign.util.toKey
import org.apache.http.HttpStatus

open class RestClientKeyProviderService(
    settings: KeyProviderSettings,
    restClientConfig: RestClientConfig,
    cacheObjectSerializer: AbstractCacheObjectSerializer<String, IKeyEntry>? = null
) : AbstractRestClientKeyProviderService(settings, restClientConfig, cacheObjectSerializer) {

    init {
        assertRestSettings()
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
                        .binding(
                            ConfigKeyBinding()
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

    fun newKeysApi(): KeysApi {
        return KeysApi(apiClient)
    }

    fun newSigningApi(): SigningApi {
        return SigningApi(apiClient)
    }

    private fun assertRestSettings() {
        if (settings.config.type != KeyProviderType.REST) {
            throw SignClientException(
                "Cannot create a REST certificate Service Provider without mode set to REST. Current mode: ${settings.config.type}"
            )
        }
    }
}
