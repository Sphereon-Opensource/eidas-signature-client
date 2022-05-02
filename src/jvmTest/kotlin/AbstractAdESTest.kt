import com.sphereon.vdx.ades.enums.CertificateProviderType
import com.sphereon.vdx.ades.model.CertificateProviderConfig
import com.sphereon.vdx.ades.model.CertificateProviderSettings
import com.sphereon.vdx.ades.model.KeystoreParameters
import com.sphereon.vdx.ades.model.PasswordInputCallback
import com.sphereon.vdx.ades.pki.CertificateProviderService
import com.sphereon.vdx.ades.sign.SignatureService

abstract class AbstractAdESTest {
    fun constructCertProviderService(
        keystoreFilename: String = "user_a_rsa.p12",
        password: String = "password"
    ): CertificateProviderService {
        val providerPath = this::class.java.classLoader.getResource(keystoreFilename).path
        val passwordInputCallback = PasswordInputCallback(password = password.toCharArray())
        val providerConfig = CertificateProviderConfig(
            type = CertificateProviderType.PKCS12,
            pkcs12Parameters = KeystoreParameters(providerPath)
        )
        return CertificateProviderService(
            CertificateProviderSettings(
                id = "pkcs12",
                providerConfig,
                passwordInputCallback
            )
        )
    }

    protected fun constructSignatureService(keystoreFilename: String = "user_a_rsa.p12", password: String = "password"): SignatureService {
        return SignatureService(constructCertProviderService(keystoreFilename, password))
    }

}
