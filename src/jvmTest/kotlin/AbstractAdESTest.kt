import com.sphereon.vdx.ades.enums.KeyProviderType
import com.sphereon.vdx.ades.model.KeyProviderConfig
import com.sphereon.vdx.ades.model.KeyProviderSettings
import com.sphereon.vdx.ades.model.KeystoreParameters
import com.sphereon.vdx.ades.model.PasswordInputCallback
import com.sphereon.vdx.ades.pki.LocalKeyProviderService
import com.sphereon.vdx.ades.sign.KeySignatureService
import com.sphereon.vdx.ades.sign.KidSignatureService

abstract class AbstractAdESTest {
    fun constructKeyProviderService(
        keystoreFilename: String = "user_a_rsa.p12",
        password: String = "password",
        enableCache: Boolean = false
    ): LocalKeyProviderService {
        val providerPath = this::class.java.classLoader.getResource(keystoreFilename).path
        val passwordInputCallback = PasswordInputCallback(password = password.toCharArray())
        val providerConfig = KeyProviderConfig(
            cacheEnabled = enableCache,
            type = KeyProviderType.PKCS12,
            pkcs12Parameters = KeystoreParameters(providerPath)
        )
        return LocalKeyProviderService(
            KeyProviderSettings(
                id = "pkcs12",
                providerConfig,
                passwordInputCallback
            )
        )
    }

    protected open fun constructKeySignatureService(
        keystoreFilename: String,
        password: String,
        enableCache: Boolean = false
    ): KeySignatureService {
        return KeySignatureService(constructKeyProviderService(keystoreFilename, password, enableCache))
    }

    protected fun constructKidSignatureService(
        keystoreFilename: String,
        password: String,
        enableCache: Boolean = false
    ): KidSignatureService {
        return KidSignatureService(constructKeyProviderService(keystoreFilename, password, enableCache))
    }
}
