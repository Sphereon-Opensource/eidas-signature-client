package com.sphereon.vdx.ades.pki

import SelfSignedCertGenerator
import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.enums.KeyProviderType
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


class LocalKeyProviderServiceTest {
    @Test
    fun `Given too few config parameters a PKI Exception occurs`() {
        val pkcs11Ex = assertFailsWith<PKIException> {
            KeyProviderServiceFactory.createFromConfig(
                KeyProviderSettings(id = "pkcs11", KeyProviderConfig(type = KeyProviderType.PKCS11))
            )
        }
        assert("PKCS11 provider without configuration" in pkcs11Ex.message!!)


        val pkcs12Ex = assertFailsWith<PKIException> {
            KeyProviderServiceFactory.createFromConfig(
                KeyProviderSettings(id = "pkcs12", KeyProviderConfig(type = KeyProviderType.PKCS12))
            )
        }
        assert("PKCS12 provider without configuration" in pkcs12Ex.message!!)


        val notSupportedEx = assertFailsWith<PKIException> {
            KeyProviderServiceFactory.createFromConfig(
                KeyProviderSettings(id = "not supported yet", KeyProviderConfig(type = KeyProviderType.JKS))
            )
        }
        assert("Config type not set or supported" in notSupportedEx.message!!)
    }


    @Test
    fun `Given an in memory pkcs12 bytearray configuration one key should be found`() {
        val testKid = "test-key"
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
        keyStore.setKeyEntry(testKid, keyPair.private, password, arrayOf(cert))
        assertNotNull(keyStore.getKey(testKid, password))
        keyStore.store(baos, password)
        val providerBytes = baos.toByteArray()
        baos.close()


        // Do the actual key provider tests with the bytearray keystore
        val passwordInputCallback = PasswordInputCallback(password = password)
        val providerConfig = KeyProviderConfig(
            type = KeyProviderType.PKCS12,
            pkcs12Parameters = KeystoreParameters(providerBytes = providerBytes)
        )
        val keyProvider =
            KeyProviderServiceFactory.createFromConfig(
                KeyProviderSettings(
                    id = "pkcs12",
                    providerConfig,
                    passwordInputCallback
                )
            )


        assertFalse(keyProvider.getKeys().isEmpty())
        assertEquals(1, keyProvider.getKeys().size)
        println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(keyProvider.getKeys()))

        assertNotNull(keyProvider.getKey(testKid))
    }


    @Test
    fun `Given a pkcs12 file configuration one certificate should be found`() {
        val providerPath = this::class.java.classLoader.getResource("good-user.p12").path
        val passwordInputCallback = PasswordInputCallback(password = "ks-password".toCharArray())
        val providerConfig = KeyProviderConfig(
            type = KeyProviderType.PKCS12,
            pkcs12Parameters = KeystoreParameters(providerPath)
        )
        val keyProvider =
            LocalKeyProviderService(
                KeyProviderSettings(
                    id = "pkcs12",
                    providerConfig,
                    passwordInputCallback
                )
            )

        assertFalse(keyProvider.getKeys().isEmpty())
        assertEquals(1, keyProvider.getKeys().size)
        assertNotNull(keyProvider.getKey("good-user"))
        println(json.encodeToString(keyProvider.getKeys().first().certificate))
        assertNull(keyProvider.getKey("does-not-exist"))
    }
}

