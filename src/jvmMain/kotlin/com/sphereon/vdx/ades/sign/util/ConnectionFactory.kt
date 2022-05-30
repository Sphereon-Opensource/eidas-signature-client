package com.sphereon.vdx.ades.sign.util

import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.enums.CertificateProviderType
import com.sphereon.vdx.ades.model.CertificateProviderConfig
import com.sphereon.vdx.ades.model.CertificateProviderSettings
import com.sphereon.vdx.ades.model.PasswordInputCallback
import com.sphereon.vdx.ades.pki.AzureKeyvaultClientConfig
import eu.europa.esig.dss.token.SignatureTokenConnection
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

object ConnectionFactory {
    init {
        Security.addProvider(BouncyCastleProvider())
    }

    fun connection(
        settings: CertificateProviderSettings, alias: String? = null,
        keyvaultConfig: AzureKeyvaultClientConfig? = null
    ): SignatureTokenConnection {
        return connection(settings.config, settings.passwordInputCallback, alias, keyvaultConfig)
    }

    fun connection(
        config: CertificateProviderConfig,
        passwordInputCallback: PasswordInputCallback? = null,
        alias: String? = null,
        azureKeyvaultClientConfig: AzureKeyvaultClientConfig? = null
    ): SignatureTokenConnection {
        return when (config.type) {
            CertificateProviderType.PKCS12 ->
                if (config.pkcs12Parameters != null) config.pkcs12Parameters.toPkcs12SignatureToken(
                    passwordInputCallback ?: config.password ?: throw PKIException("No password provided")
                )
                else throw PKIException("Cannot create a PKCS12 provider without configuration")
            CertificateProviderType.PKCS11 ->
                if (config.pkcs11Parameters != null) config.pkcs11Parameters.toPkcs11SignatureToken()
                else throw PKIException("Cannot create a PKCS11 provider without configuration")
            CertificateProviderType.AZURE_KEYVAULT -> {
                requireNotNull(azureKeyvaultClientConfig) { "Keyvault client config is needed for azure connection" }
                requireNotNull(alias) { "Cannot create an azure connection without the alis" }
                azureKeyvaultClientConfig.toAzureSignatureToken(alias = alias)
            }

            else -> throw PKIException("Config type not set or supported (yet): " + config.type)
        }
    }
}
