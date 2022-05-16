package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.enums.CertificateProviderType
import com.sphereon.vdx.ades.enums.CryptoAlg
import com.sphereon.vdx.ades.model.CertificateProviderSettings
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.KeyEntry
import com.sphereon.vdx.ades.rest.client.ApiClient
import com.sphereon.vdx.ades.rest.client.api.CertificatesApi
import com.sphereon.vdx.ades.sign.util.CertificateUtil
import com.sphereon.vdx.ades.sign.util.toCertificate
import java.time.Duration


open class RESTCertificateProviderService(override val settings: CertificateProviderSettings) : ICertificateProviderService {

    private val cacheService = CacheService(settings)

    private val apiClients: MutableMap<String, ApiClient> = mutableMapOf()

    init {
        if (settings.config.type != CertificateProviderType.REST) {
            throw SignClientException("Cannot create a REST certificate Service Provider without mode set to REST. Current mode: ${settings.config.type}")
        }
    }

    override fun getKeys(): List<IKeyEntry> {
        throw SignClientException("Retrieving multiple certificates using the REST client is not possible")
    }

    override fun getKey(alias: String): IKeyEntry? {
        val cachedKey = cacheService.get(alias)
        if (cachedKey != null) {
            return cachedKey
        }

        val certApi = getCertApi()
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

    fun getCertApi(): CertificatesApi {
        return CertificatesApi(getApiClient())
    }

    private fun getApiClient(): ApiClient {
        val baseUrl = this.settings.config.restConfig?.baseUrl ?: "https://localhost"

        if (apiClients.containsKey(baseUrl)) {
            return apiClients[baseUrl]!!
        }

        
        val apiClient = ApiClient()

        if (baseUrl != null) {
            apiClient.updateBaseUri(baseUrl)
        }
        if (settings.config.restConfig?.connectTimeoutInMS != null) {
            apiClient.connectTimeout = Duration.ofMillis(settings.config.restConfig!!.connectTimeoutInMS!!)
        }
        if (settings.config.restConfig?.readTimeoutInMS != null) {
            apiClient.readTimeout = Duration.ofMillis(settings.config.restConfig!!.readTimeoutInMS!!)
        }
        apiClients[baseUrl] = apiClient
        return apiClient
    }
}
