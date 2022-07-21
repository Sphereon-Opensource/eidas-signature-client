package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.enums.DigestAlg
import com.sphereon.vdx.ades.enums.KeyProviderType
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.model.SignInput
import com.sphereon.vdx.ades.rest.client.ApiResponse
import com.sphereon.vdx.ades.rest.client.JSON
import com.sphereon.vdx.ades.rest.client.api.KeysApi
import com.sphereon.vdx.ades.rest.client.api.SigningApi
import com.sphereon.vdx.ades.rest.client.model.*
import com.sphereon.vdx.ades.rest.client.model.ConfigKeyBinding
import com.sphereon.vdx.ades.rest.client.model.Signature
import io.mockk.every
import io.mockk.mockk
import io.mockk.spyk
import kotlinx.datetime.*
import kotlinx.datetime.TimeZone
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.*

class RestCertificateProviderServiceTest {
    @Test
    fun `Given a KID the REST Certificate Provider Service should return a key`() {
        assertNotNull(key)
        assertEquals(KID_REST, key.kid)
        assertNotNull(key.certificate)
        assertEquals("1A485229434026D47F47ADE3BDCA499253F588C0", key.certificate?.fingerPrint)
        assertEquals("C=LU, OU=PKI-TEST, O=Nowina Solutions, CN=good-ca", key.certificate?.issuerDN)
        assertEquals("C=LU, OU=PKI-TEST, O=Nowina Solutions, CN=good-user", key.certificate?.subjectDN)
        assertEquals("10", key.certificate?.serialNumber)
        assertNotNull(key.certificate?.keyUsage)
        assertEquals(9, key.certificate?.keyUsage!!.size)
        assertEquals(true, key.certificate?.keyUsage!!["nonRepudiation"])
        assertEquals(LocalDateTime.parse("2021-04-01T15:00:16").toInstant(TimeZone.UTC), key.certificate?.notBefore)
        assertEquals(LocalDateTime.parse("2023-02-01T15:00:16").toInstant(TimeZone.UTC), key.certificate?.notAfter)
        assertNotNull(key.certificateChain)
        assertEquals(3, key.certificateChain!!.size)
        // We already tested a certificate above. So we only test for proper order of the cert chain here
        assertEquals("1A485229434026D47F47ADE3BDCA499253F588C0", key.certificateChain!![0].fingerPrint)
        assertEquals("9198F0B98F86315152C2B27D74112D422D111BF0", key.certificateChain!![1].fingerPrint)
        assertEquals("F013A0FD6D5B45D2DD1792879545AAB1CA6117EA", key.certificateChain!![2].fingerPrint)
    }

    @Test
    fun `Should create signature`() {
        val signature = keyProvider.createSignature(signInput, key)

        assertNotNull(signature)
        assertEquals(KID_REST, signature.providerId)
        assertNotNull(signature.signMode)
        assertNotNull(signature.algorithm)
        assertNotNull(signature.date)
        assertNotNull(signature.keyEntry)
        assertEquals(key, signature.keyEntry)
    }

    companion object {
        private val KID_REST: String = "rest"
        private lateinit var keyProvider: RestClientKeyProviderService
        private lateinit var key: IKeyEntry
        private lateinit var signInput: SignInput

        private fun constructRestClientConfig(baseUrl: String? = "http://mocked"): RestClientConfig {
            return RestClientConfig(
                baseUrl = baseUrl
            )
        }

        private fun constructKeyProviderSettings(
            password: String = "password",
            enableCache: Boolean = false
        ): KeyProviderSettings {

            return KeyProviderSettings(
                id = "rest",
                config = KeyProviderConfig(
                    cacheEnabled = enableCache,
                    type = KeyProviderType.REST,

                    ),
                passwordInputCallback = PasswordInputCallback(password = password.toCharArray())
            )

        }

        private fun setupKeyProviderMock(): RestClientKeyProviderService {
            val certApiMock = mockk<KeysApi>()
            val signingApiMock = mockk<SigningApi>()

            every {
                certApiMock.getKeyWithHttpInfo(KID_REST, KID_REST)
            } returns ApiResponse(
                200,
                emptyMap(),
                JSON.getDefault().mapper.readValue(this::class.java.classLoader.getResource("keyEntry.json"), KeyResponse::class.java)
            )

            signInput = SignInput(
                input = "data".toByteArray(),
                signMode = SignMode.DOCUMENT,
                signingDate = Clock.System.now(),
                digestAlgorithm = DigestAlg.SHA256,
                binding = com.sphereon.vdx.ades.model.ConfigKeyBinding(
                    kid = KID_REST,
                    signatureConfigId = "1",
                    keyProviderId = KID_REST
                )
            )
            every {
                signingApiMock.createSignature(
                    CreateSignature()
                        .signInput(
                            com.sphereon.vdx.ades.rest.client.model.SignInput()
                                .name(signInput.name)
                                .input(signInput.input)
                                .signMode(com.sphereon.vdx.ades.rest.client.model.SignMode.valueOf(signInput.signMode.name))
                                .digestAlgorithm(signInput.digestAlgorithm?.name?.let { DigestAlgorithm.valueOf(it) })
                                .signingDate(Instant.ofEpochSecond(signInput.signingDate.epochSeconds))
                                .binding(
                                    ConfigKeyBinding()
                                        .kid(KID_REST)
                                        .keyProviderId(KID_REST)
                                )
                        )
                )

            } returns CreateSignatureResponse()
                .signature(
                    Signature()
                        .value("ZGF0YQ==".toByteArray())
                        .algorithm(SignatureAlgorithm.RSA_SHA256)
                        .signMode(com.sphereon.vdx.ades.rest.client.model.SignMode.DOCUMENT)
                        .binding(
                            ConfigKeyBinding()
                                .keyProviderId(KID_REST)
                                .kid(KID_REST)
                        )
                        .date(Instant.now())
                )

            val keyProvider = spyk(RestClientKeyProviderService(constructKeyProviderSettings(), constructRestClientConfig()))
            every {
                keyProvider.newKeysApi()
            } returns certApiMock
            every {
                keyProvider.newSigningApi()
            } returns signingApiMock
            return keyProvider
        }

        @BeforeAll
        @JvmStatic
        internal fun init() {
            keyProvider = setupKeyProviderMock()
            key = keyProvider.getKey(KID_REST)!!
        }
    }
}
