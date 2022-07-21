package com.sphereon.vdx.ades.pki

import AbstractCacheObjectSerializer
import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.enums.KeyProviderType
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.KeyProviderSettings

object KeyProviderServiceFactory {

    fun createFromConfig(
        settings: KeyProviderSettings,
        restClientConfig: RestClientConfig? = null,
        azureKeyvaultClientConfig: AzureKeyvaultClientConfig? = null,
        cacheObjectSerializer: AbstractCacheObjectSerializer<String, IKeyEntry>? = null
    ): IKeyProviderService {
        return when (settings.config.type) {
            KeyProviderType.REST -> {
                RestClientKeyProviderService(
                    settings,
                    restClientConfig
                        ?: throw SignClientException("Cannot create REST key provider without providing a REST client config"),
                    cacheObjectSerializer
                )
            }
            KeyProviderType.AZURE_KEYVAULT -> {
                AzureKeyvaultKeyProviderService(
                    settings,
                    azureKeyvaultClientConfig
                        ?: throw SignClientException("Cannot create a Azure Keyvault key provider without providing a Azure Keyvault client config"),
                    cacheObjectSerializer
                )
            }
            else -> {
                LocalKeyProviderService(settings, cacheObjectSerializer)
            }
        }
    }
}
