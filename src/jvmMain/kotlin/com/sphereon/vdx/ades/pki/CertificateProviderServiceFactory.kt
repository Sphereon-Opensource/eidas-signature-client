package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.enums.CertificateProviderType
import com.sphereon.vdx.ades.model.CertificateProviderSettings

object CertificateProviderServiceFactory {

    fun createFromConfig(settings: CertificateProviderSettings): ICertificateProviderService {
        return if (settings.config.type == CertificateProviderType.REST) {
            RESTCertificateProviderService(settings)
        } else {
            LocalCertificateProviderService(settings)
        }
    }

}
