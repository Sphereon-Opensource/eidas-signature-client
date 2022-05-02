package com.sphereon.vdx.ades.sign.util

import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.enums.CertificateProviderType
import com.sphereon.vdx.ades.model.CertificateProviderConfig
import com.sphereon.vdx.ades.model.CertificateProviderSettings
import com.sphereon.vdx.ades.model.PasswordInputCallback
import eu.europa.esig.dss.token.SignatureTokenConnection
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

object ConnectionFactory {
    init {
        Security.addProvider(BouncyCastleProvider())
    }

    fun connection(settings: CertificateProviderSettings): SignatureTokenConnection {
        return connection(settings.config, settings.passwordInputCallback)
    }

    fun connection(config: CertificateProviderConfig, passwordInputCallback: PasswordInputCallback? = null): SignatureTokenConnection {
        return when (config.type) {
            CertificateProviderType.PKCS12 ->
                if (config.pkcs12Parameters != null) config.pkcs12Parameters.toPkcs12SignatureToken(
                    passwordInputCallback ?: config.password ?: throw PKIException("No password provided")
                )
                else throw PKIException("Cannot create a PKCS12 provider without configuration")
            CertificateProviderType.PKCS11 ->
                if (config.pkcs11Parameters != null) config.pkcs11Parameters.toPkcs11SignatureToken()
                else throw PKIException("Cannot create a PKCS11 provider without configuration")
            else -> throw PKIException("Config type not set or supported (yet): " + config.type)
        }
    }
}
