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
        val key = keyProvider.getKey("7e13564x-88am-0621-p4l5-56e7312344as")

        assertNotNull(key)
        assertEquals("7e13564x-88am-0621-p4l5-56e7312344as", key.kid)
        assertNotNull(key.publicKey)
        assertEquals("X.509", key.publicKey.format)
        assertEquals(CryptoAlg.RSA, key.publicKey.algorithm)
        assertEquals("59F815EF01229B27147BB84F2F412C16C5BD6BE0", key.certificate?.fingerPrint)
        assertEquals(
            "CN=Ensured Document Signing CA, O=Ensured B.V., L=Heerhugowaard, ST=Noord-Holland, C=NL",
            key.certificate?.issuerDN
        )
        assertEquals(
            "EMAILADDRESS=signature@esignum.io, CN=Afdeling beheer, OU=Afdeling beheer, O=Sphereon B.V., ST=Utrecht, C=NL",
            key.certificate?.subjectDN
        )
        assertEquals("302503097311715737064467329723821046857", key.certificate?.serialNumber)
        assertNotNull(key.certificate?.keyUsage)
        assertEquals(9, key.certificate?.keyUsage!!.size)
        assertEquals(true, key.certificate?.keyUsage!!["digitalSignature"])
        assertEquals(true, key.certificate?.keyUsage!!["nonRepudiation"])
        assertEquals(LocalDateTime.parse("2021-08-31T00:00:00").toInstant(TimeZone.UTC), key.certificate?.notBefore)
        assertEquals(LocalDateTime.parse("2024-08-30T23:59:59").toInstant(TimeZone.UTC), key.certificate?.notAfter)

        assertNotNull(key.certificateChain)
        assertEquals(4, key.certificateChain!!.size)
        // We already tested a certificate above. So we only test for proper order of the cert chain here
        assertEquals("59F815EF01229B27147BB84F2F412C16C5BD6BE0", key.certificateChain!![0].fingerPrint)
        assertEquals("2F8E604EBE9CD29F08C3EA5BCE79B9D85CC5091D", key.certificateChain!![1].fingerPrint)
        assertEquals("EF6C68DDE05896655EF293CF05331F86FB17D8E6", key.certificateChain!![2].fingerPrint)
        assertEquals("D89E3BD43D5D909B47A18977AA9D5CE36CEE184C", key.certificateChain!![3].fingerPrint)

    }


    private fun constructProviderConfig(): DigidentityProviderConfig {
        return DigidentityProviderConfig(
            baseUrl = "https://api.digidentity-preproduction.eu/v1",
            autoSignerId = "7e13564x-88am-0621-p4l5-56e7312344as",
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
