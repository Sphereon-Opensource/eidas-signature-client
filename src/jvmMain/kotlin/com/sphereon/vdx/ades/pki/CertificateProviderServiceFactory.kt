package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.RestClientConfig
import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.enums.CertificateProviderType
import com.sphereon.vdx.ades.model.CertificateProviderSettings

object CertificateProviderServiceFactory {

    fun createFromConfig(settings: CertificateProviderSettings, restClientConfig: RestClientConfig? = null): ICertificateProviderService {
        return if (settings.config.type == CertificateProviderType.REST) {
            RestCertificateProviderService(
                settings,
                restClientConfig ?: throw SignClientException("Cannot create a REST certificate provider without providing a REST client config")
            )
        } else {
            LocalCertificateProviderService(settings)
        }
    }

}
