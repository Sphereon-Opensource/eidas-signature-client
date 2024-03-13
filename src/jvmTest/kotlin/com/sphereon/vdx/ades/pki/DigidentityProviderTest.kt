package com.sphereon.vdx.ades.pki

import AbstractAdESTest
import KeyEntryCacheSerializer
import com.sphereon.vdx.ades.enums.CryptoAlg
import com.sphereon.vdx.ades.enums.KeyProviderType
import com.sphereon.vdx.ades.model.KeyProviderConfig
import com.sphereon.vdx.ades.model.KeyProviderSettings
import com.sphereon.vdx.ades.pki.digidentity.DigidentityCredentialMode
import com.sphereon.vdx.ades.pki.digidentity.DigidentityCredentialOpts
import com.sphereon.vdx.ades.pki.digidentity.DigidentityProviderConfig
import com.sphereon.vdx.ades.pki.digidentity.DigidentitySecretCredentialOpts
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toInstant
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class DigidentityProviderTest : AbstractAdESTest() {
    @Test
    fun `Given a KID the Azure Keyvault Certificate Provider Service should return a key`() {
        val keyProvider = KeyProviderServiceFactory.createFromConfig(constructCertificateProviderSettings(true)) {
            digidentityProviderConfig = constructProviderConfig()
            cacheObjectSerializer = KeyEntryCacheSerializer()
        }
        val key = keyProvider.getKey("9b2b85df-9149-4440-a7a7-67953a38b832")

        assertNotNull(key)
        assertEquals("9b2b85df-9149-4440-a7a7-67953a38b832", key.kid)
        assertNotNull(key.publicKey)
        assertEquals("X.509", key.publicKey.format)
        assertEquals(CryptoAlg.RSA, key.publicKey.algorithm)
        assertEquals("D5D0075C981C4462BAB99737E9BE0C49F750BB63", key.certificate?.fingerPrint)
        assertEquals(
            "C=NL, O=Digidentity B.V., OID.2.5.4.97=NTRNL-27322631, CN=TEST Digidentity Business Qualified CA",
            key.certificate?.issuerDN
        )
        assertEquals(
            "C=NL, O=Regional Sanjoflex, OID.2.5.4.97=NTRNL-90002768, CN=Regional Sanjoflex",
            key.certificate?.subjectDN
        )
        assertEquals("70155151975609048911381342004623025095", key.certificate?.serialNumber)
        assertNotNull(key.certificate?.keyUsage)
        assertEquals(9, key.certificate?.keyUsage!!.size)
        assertEquals(false, key.certificate?.keyUsage!!["digitalSignature"]) // TODO Double-check if this shouldn't be true
        assertEquals(true, key.certificate?.keyUsage!!["nonRepudiation"])
        assertEquals(LocalDateTime.parse("2024-02-19T11:05:18").toInstant(TimeZone.UTC), key.certificate?.notBefore)
        assertEquals(LocalDateTime.parse("2025-02-18T11:05:17").toInstant(TimeZone.UTC), key.certificate?.notAfter) // TODO Hmmz this will assure the build will fail next year

        assertNotNull(key.certificateChain)
        assertEquals(3, key.certificateChain!!.size)
        // We already tested a certificate above. So we only test for proper order of the cert chain here
        assertEquals("D5D0075C981C4462BAB99737E9BE0C49F750BB63", key.certificateChain!![0].fingerPrint)
        assertEquals("9F9CFCE17EA78D9510D9A598453DC05BCC532053", key.certificateChain!![1].fingerPrint)
        assertEquals("719AFB0F5D19A3F3FD64E7D7065E9147328EBA6C", key.certificateChain!![2].fingerPrint)
    }


    private fun constructProviderConfig(): DigidentityProviderConfig {
        return DigidentityProviderConfig(
            baseUrl = "https://api.digidentity-preproduction.eu/v1",
            autoSignerId = "9b2b85df-9149-4440-a7a7-67953a38b832",
            credentialOpts = DigidentityCredentialOpts(
                credentialMode = DigidentityCredentialMode.SERVICE_CLIENT_SECRET,
                secretCredentialOpts = DigidentitySecretCredentialOpts(
                    clientId = System.getenv("DG_CLIENT_ID"),
                    clientSecret = System.getenv("DG_CLIENT_SECRET"),
                    apiKey = System.getenv("DG_API_KEY"),
                )
            )
        )
    }

    private fun constructCertificateProviderSettings(
        enableCache: Boolean? = true
    ): KeyProviderSettings {
        return KeyProviderSettings(
            id = "7e13564x-88am-0621-p4l5-56e7312344as",
            config = KeyProviderConfig(
                cacheEnabled = enableCache,
                type = KeyProviderType.DIGIDENTITY
            )
        )
    }
}
