package com.sphereon.vdx.ades.pki

import SelfSignedCertGenerator
import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.enums.CertificateProviderType
import com.sphereon.vdx.ades.model.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import kotlin.test.*


class LocalCertificateProviderServiceTest {
    @Test
    fun `Given too few config parameters a PKI Exception occurs`() {
        val pkcs11Ex = assertFailsWith<PKIException> {
            CertificateProviderServiceFactory.createFromConfig(
                CertificateProviderSettings(id = "pkcs11", CertificateProviderConfig(type = CertificateProviderType.PKCS11))
            )
        }
        assert("PKCS11 provider without configuration" in pkcs11Ex.message!!)


        val pkcs12Ex = assertFailsWith<PKIException> {
            CertificateProviderServiceFactory.createFromConfig(
                CertificateProviderSettings(id = "pkcs12", CertificateProviderConfig(type = CertificateProviderType.PKCS12))
            )
        }
        assert("PKCS12 provider without configuration" in pkcs12Ex.message!!)


        val notSupportedEx = assertFailsWith<PKIException> {
            CertificateProviderServiceFactory.createFromConfig(
                CertificateProviderSettings(id = "not supported yet", CertificateProviderConfig(type = CertificateProviderType.JKS))
            )
        }
        assert("Config type not set or supported" in notSupportedEx.message!!)
    }


    @Test
    fun `Given an in memory pkcs12 bytearray configuration one certificate should be found`() {
        val testKeyAlias = "test-key"
        val password = "password".toCharArray()
        val baos = ByteArrayOutputStream()

        // Setup the key pair, generate certificate
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(4096)
        val keyPair: KeyPair = keyPairGenerator.generateKeyPair()
        val cert: X509Certificate = SelfSignedCertGenerator.generate(keyPair, "SHA256withRSA", "CN=testcert", 1)

        // Setup keystore and store it in a byte array
        val keyStore = KeyStore.getInstance("PKCS12")
        keyStore.load(null, password)
        keyStore.setKeyEntry(testKeyAlias, keyPair.private, password, arrayOf(cert))
        assertNotNull(keyStore.getKey(testKeyAlias, password))
        keyStore.store(baos, password)
        val providerBytes = baos.toByteArray()
        baos.close()


        // Do the actual cert provider tests with the bytearray keystore
        val passwordInputCallback = PasswordInputCallback(password = password)
        val providerConfig = CertificateProviderConfig(
            type = CertificateProviderType.PKCS12,
            pkcs12Parameters = KeystoreParameters(providerBytes = providerBytes)
        )
        val certProvider =
            CertificateProviderServiceFactory.createFromConfig(
                CertificateProviderSettings(
                    id = "pkcs12",
                    providerConfig,
                    passwordInputCallback
                )
            )


        assertFalse(certProvider.getKeys().isEmpty())
        assertEquals(1, certProvider.getKeys().size)
        println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(certProvider.getKeys()))

        assertNotNull(certProvider.getKey(testKeyAlias))
    }


    @Test
    fun `Given a pkcs12 file configuration one certificate should be found`() {
        val providerPath = this::class.java.classLoader.getResource("good-user.p12").path
        val passwordInputCallback = PasswordInputCallback(password = "ks-password".toCharArray())
        val providerConfig = CertificateProviderConfig(
            type = CertificateProviderType.PKCS12,
            pkcs12Parameters = KeystoreParameters(providerPath)
        )
        val certProvider =
            LocalCertificateProviderService(
                CertificateProviderSettings(
                    id = "pkcs12",
                    providerConfig,
                    passwordInputCallback
                )
            )

        assertFalse(certProvider.getKeys().isEmpty())
        assertEquals(1, certProvider.getKeys().size)
        assertNotNull(certProvider.getKey("good-user"))
        println(json.encodeToString(certProvider.getKeys().first().certificate))
        assertNull(certProvider.getKey("does-not-exist"))
    }
}

