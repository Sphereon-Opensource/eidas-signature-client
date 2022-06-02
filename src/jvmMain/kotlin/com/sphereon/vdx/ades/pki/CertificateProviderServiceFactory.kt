package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.enums.CertificateProviderType
import com.sphereon.vdx.ades.model.CertificateProviderConfig
import com.sphereon.vdx.ades.model.CertificateProviderSettings

object CertificateProviderServiceFactory {

    fun createFromConfig(
        settings: CertificateProviderSettings,
        restClientConfig: RestClientConfig? = null,
        azureKeyvaultClientConfig: AzureKeyvaultClientConfig? = null
    ): ICertificateProviderService {
        return when (settings.config.type) {
            CertificateProviderType.REST -> {
                RestCertificateProviderService(
                    settings,
                    restClientConfig
                        ?: throw SignClientException("Cannot create a REST certificate provider without providing a REST client config")
                )
            }
            CertificateProviderType.AZURE_KEYVAULT -> {
                AzureKeyvaultCertificateProviderService(
                    settings,
                    azureKeyvaultClientConfig
                        ?: throw SignClientException("Cannot create a Azure Keyvault certificate provider without providing a Azure Keyvault client config")
                )
            }
            else -> {
                LocalCertificateProviderService(settings)
            }
        }
    }
}
