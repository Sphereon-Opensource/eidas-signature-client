package com.sphereon.vdx.ades.sign.util

import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.enums.KeyProviderType
import com.sphereon.vdx.ades.model.KeyProviderConfig
import com.sphereon.vdx.ades.model.KeyProviderSettings
import com.sphereon.vdx.ades.model.PasswordInputCallback
import com.sphereon.vdx.ades.pki.azure.AzureKeyvaultClientConfig
import eu.europa.esig.dss.token.SignatureTokenConnection
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

object ConnectionFactory {
    init {
        Security.addProvider(BouncyCastleProvider())
    }

    fun connection(
        settings: KeyProviderSettings, kid: String? = null,
        keyvaultConfig: AzureKeyvaultClientConfig? = null
    ): SignatureTokenConnection {
        return connection(settings.config, settings.passwordInputCallback, kid, keyvaultConfig)
    }

    fun connection(
        config: KeyProviderConfig,
        passwordInputCallback: PasswordInputCallback? = null,
        kid: String? = null,
        azureKeyvaultClientConfig: AzureKeyvaultClientConfig? = null
    ): SignatureTokenConnection {
        return when (config.type) {
            KeyProviderType.PKCS12 ->
                if (config.pkcs12Parameters != null) config.pkcs12Parameters.toPkcs12SignatureToken(
                    passwordInputCallback ?: config.password ?: throw PKIException("No password provided")
                )
                else throw PKIException("Cannot create a PKCS12 provider without configuration")
            KeyProviderType.PKCS11 ->
                if (config.pkcs11Parameters != null) config.pkcs11Parameters.toPkcs11SignatureToken()
                else throw PKIException("Cannot create a PKCS11 provider without configuration")
            KeyProviderType.AZURE_KEYVAULT -> {
                requireNotNull(azureKeyvaultClientConfig) { "Keyvault client config is needed for azure connection" }
                requireNotNull(kid) { "Cannot create an azure connection without the kid" }
                azureKeyvaultClientConfig.toAzureSignatureToken(kid = kid)
            }

            else -> throw PKIException("Config type not set or supported (yet): " + config.type)
        }
    }
}
