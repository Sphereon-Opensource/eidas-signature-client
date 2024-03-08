package com.sphereon.vdx.ades.pki

import AbstractCacheObjectSerializer
import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.enums.KeyProviderType
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.KeyProviderSettings
import com.sphereon.vdx.ades.pki.azure.AzureKeyvaultClientConfig
import com.sphereon.vdx.ades.pki.azure.AzureKeyvaultKeyProviderService
import com.sphereon.vdx.ades.pki.digidentity.DigidentityKeyProviderService
import com.sphereon.vdx.ades.pki.digidentity.DigidentityProviderConfig

object KeyProviderServiceFactory {

    data class CreateOptions(
        var restClientConfig: RestClientConfig? = null,
        var azureKeyvaultClientConfig: AzureKeyvaultClientConfig? = null,
        var digidentityProviderConfig: DigidentityProviderConfig? = null,
        var cacheObjectSerializer: AbstractCacheObjectSerializer<String, IKeyEntry>? = null
    )

    fun createFromConfig(
        settings: KeyProviderSettings,
        createOptions: CreateOptions.() -> Unit = {}
    ): IKeyProviderService {
        val options = CreateOptions().apply(createOptions)

        return when (settings.config.type) {
            KeyProviderType.REST -> {
                RestClientKeyProviderService(
                    settings,
                    options.restClientConfig
                        ?: throw SignClientException("Cannot create REST key provider without providing a REST client config"),
                    options.cacheObjectSerializer
                )
            }

            KeyProviderType.AZURE_KEYVAULT -> {
                AzureKeyvaultKeyProviderService(
                    settings,
                    options.azureKeyvaultClientConfig
                        ?: throw SignClientException("Cannot create a Azure Keyvault key provider without providing a Azure Keyvault client config"),
                    options.cacheObjectSerializer
                )
            }

            KeyProviderType.DIGIDENTITY -> {
                DigidentityKeyProviderService(
                    settings,
                    options.digidentityProviderConfig
                        ?: throw SignClientException("Cannot create a Digidentity key provider without providing a Digidentity provider config"),
                    options.cacheObjectSerializer
                )
            }

            else -> {
                LocalKeyProviderService(settings, options.cacheObjectSerializer)
            }
        }
    }
}
