package com.sphereon.vdx.ades.pki

import AbstractAdESTest
import KeyEntryCacheSerializer
import com.sphereon.vdx.ades.enums.*
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.sign.KidSignatureService
import com.sphereon.vdx.ades.sign.util.toX509Certificate
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource
import eu.europa.esig.dss.validation.CommonCertificateVerifier
import eu.europa.esig.dss.validation.executor.ValidationLevel
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toInstant
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

const val SIGDATE = "2022-06-01T21:00:00Z"

class AzureKeyvaultCertificateProviderServiceTest : AbstractAdESTest() {


    @Test
    fun `Given a KID the Azure Keyvault Certificate Provider Service should return a key`() {
        val keyProvider = KeyProviderServiceFactory.createFromConfig(
            constructCertificateProviderSettings(true),
            azureKeyvaultClientConfig = constructKeyvaultClientConfig(),
            cacheObjectSerializer = KeyEntryCacheSerializer()
        )
        val key = keyProvider.getKey("esignum:3f98a9a740fb41b79e3679cce7a34ba6")

        assertNotNull(key)
        assertEquals("esignum:3f98a9a740fb41b79e3679cce7a34ba6", key.kid)
        assertNotNull(key.publicKey)
        assertEquals("X.509", key.publicKey.format)
        assertEquals(CryptoAlg.RSA, key.publicKey.algorithm)
        assertEquals("59F815EF01229B27147BB84F2F412C16C5BD6BE0", key.certificate?.fingerPrint)
        assertEquals("CN=Ensured Document Signing CA, O=Ensured B.V., L=Heerhugowaard, ST=Noord-Holland, C=NL", key.certificate?.issuerDN)
        assertEquals(
            "EMAILADDRESS=signature@esignum.io, CN=Afdeling beheer, OU=Afdeling beheer, O=Sphereon B.V., ST=Utrecht, C=NL", key.certificate?.subjectDN
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

    @Test
    fun `Given an input with signmode DOCUMENT and DIGEST the sign method should sign the document`() {
        val pdfDocInput = this::class.java.classLoader.getResource("test-unsigned.pdf")
        val logo = this::class.java.classLoader.getResource("logo.png")
        val pdfData = OrigData(value = pdfDocInput.readBytes(), name = "test-unsigned.pdf")
        val logoData = OrigData(value = logo.readBytes(), name = "sphereon.png", mimeType = "image/png")


        val keyProvider = KeyProviderServiceFactory.createFromConfig(
            constructCertificateProviderSettings(false), azureKeyvaultClientConfig = constructKeyvaultClientConfig()
        )
        val signingService = KidSignatureService(keyProvider)
        val kid = "esignum:3f98a9a740fb41b79e3679cce7a34ba6"
        val signatureConfiguration = SignatureConfiguration(

            signatureParameters = SignatureParameters(
                signaturePackaging = SignaturePackaging.ENVELOPED,
                digestAlgorithm = DigestAlg.SHA256,
                encryptionAlgorithm = CryptoAlg.RSA,
                signatureAlgorithm = SignatureAlg.RSA_SHA256,
                signatureLevelParameters = SignatureLevelParameters(
                    signatureLevel = SignatureLevel.PAdES_BASELINE_LTA, bLevelParameters = BLevelParams(
//                        signingDate = Instant.parse(SIGDATE)
                    )
                ),
                signatureFormParameters = SignatureFormParameters(
                    padesSignatureFormParameters = PadesSignatureFormParameters(
                        mode = PdfSignatureMode.CERTIFICATION,
                        signerName = "Test Case",
                        contactInfo = "support@sphereon.com",
                        reason = "Test",
                        location = "Online",
                        signatureSize = 15000,
                        signatureSubFilter = PdfSignatureSubFilter.ETSI_CADES_DETACHED.specName,
                        signingTimeZone = "GMT-3",
                        visualSignatureParameters = VisualSignatureParameters(
                            fieldParameters = VisualSignatureFieldParameters(
//                                fieldId = "SigNK",
                                originX = 50f,
                                originY = 400f,
                            ), image = logoData,
//                            rotation = VisualSignatureRotation.ROTATE_90,
                            textParameters = VisualSignatureTextParameters(
                                text = "Niels Klomp\r\nCTO", signerTextPosition = SignerTextPosition.TOP
                            )

                        )

                    )
                )
            ), timestampParameters = TimestampParameters(
                tsaUrl = "http://timestamping.ensuredca.com/", baselineLTAArchiveTimestampParameters = TimestampParameterSettings(
                    digestAlgorithm = DigestAlg.SHA256
                )
            )
        )
        val signInput = signingService.determineSignInput(
            origData = pdfData, kid = kid, signMode = SignMode.DOCUMENT, signatureConfiguration = signatureConfiguration
        )

//        println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(signInput))

        // Let's first create a signature of the document/data without creating a digest
        val signatureData = signingService.createSignature(signInput, kid)
        assertNotNull(signatureData)
        assertEquals(SignMode.DOCUMENT, signatureData.signMode)
        assertEquals(SignatureAlg.RSA_SHA256, signatureData.algorithm)

        // Let's create a digest ourselves and sign that as well
        val digestInput = signingService.digest(signInput)
        val signatureDigest = signingService.createSignature(digestInput, kid)
        assertNotNull(signatureDigest)
        assertEquals(SignMode.DIGEST, signatureDigest.signMode)
        assertEquals(SignatureAlg.RSA_RAW, signatureDigest.algorithm)

        assertContentEquals(signatureData.value, signatureDigest.value)
        assertEquals(signatureData.keyEntry.certificate!!.fingerPrint, signatureDigest.keyEntry.certificate!!.fingerPrint)
        assertEquals(signatureData.keyEntry.certificateChain!![3].fingerPrint, signatureDigest.keyEntry.certificateChain!![3].fingerPrint)

        val signOutputData = signingService.sign(pdfData, signatureData, signatureConfiguration)
        assertNotNull(signOutputData)

        val signOutputDigest = signingService.sign(pdfData, signatureDigest, signatureConfiguration)
        assertNotNull(signOutputDigest)



        InMemoryDocument(signOutputDigest.value, signOutputData.name).save("" + System.currentTimeMillis() + "-sphereon-signed.pdf")

        val validSignatureData = signingService.isValidSignature(signInput, signatureData, kid)
        assertTrue(validSignatureData)

        val validSignatureDigest = signingService.isValidSignature(digestInput, signatureDigest, kid)
        assertTrue(validSignatureDigest)

        assertTrue(signingService.isValidSignature(signInput, signatureData, signatureData.keyEntry.publicKey))
        assertTrue(signingService.isValidSignature(digestInput, signatureDigest, signatureDigest.keyEntry.publicKey))
        val documentValidator = PDFDocumentValidator(
            InMemoryDocument(
                signOutputData.value, signOutputData.name
            )
        )
        documentValidator.setValidationLevel(ValidationLevel.BASIC_SIGNATURES)
        documentValidator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_CERTIFICATES_AND_REVOCATION_DATA)

        val certVerifier = CommonCertificateVerifier()

        // Create an instance of a trusted certificate source
        val trustedCertSource = CommonTrustedCertificateSource()
        // Include the chain, but not the signing cert itself
        signatureDigest.keyEntry.certificateChain!!.subList(1, 3).map { trustedCertSource.addCertificate(CertificateToken(it.toX509Certificate())) }
        // Add trust anchors (trusted list, keystore,...) to a list of trusted certificate sources
        certVerifier.addTrustedCertSources(trustedCertSource)
        documentValidator.setCertificateVerifier(certVerifier)

        assertEquals(1, documentValidator.signatures.size)

        val validatedDocument = documentValidator.validateDocument()
        assertEquals(1, validatedDocument.simpleReport.validSignaturesCount)

        val diagData = documentValidator.diagnosticData
        assertEquals(1, diagData.signatures.size)
        assertEquals(6, diagData.usedCertificates.size)

        assertContentEquals(signatureDigest.value, documentValidator.signatures.first().signatureValue)
        val origDoc = documentValidator.getOriginalDocuments(documentValidator.signatures.first()).first()
        ByteArrayOutputStream().use { baos ->
            origDoc.writeTo(baos)
            assertContentEquals(pdfData.value, baos.toByteArray())
        }

    }


    private fun constructKeyvaultClientConfig(): AzureKeyvaultClientConfig {
        return AzureKeyvaultClientConfig(
            applicationId = "unit-test",
            keyvaultUrl = "https://sphereon-certs.vault.azure.net/",
            tenantId = "e2a42b2f-7460-4499-afc2-425315ef058a",
            hsmType = HSMType.KEYVAULT,
            exponentialBackoffRetryOpts = ExponentialBackoffRetryOpts(),
            credentialOpts = CredentialOpts(
                credentialMode = CredentialMode.SERVICE_CLIENT_SECRET, secretCredentialOpts = SecretCredentialOpts(
                    clientId = "d1570d88-02ff-4c98-b5e6-49eda718708f",
                    clientSecret = "_sug439PHn8745_YG-4CzcNr_CKTFLTljW",
                )
            )
        )
    }

    private fun constructCertificateProviderSettings(
        enableCache: Boolean? = false
    ): KeyProviderSettings {

        return KeyProviderSettings(
            id = "esignum-test", config = KeyProviderConfig(
                cacheEnabled = enableCache, type = KeyProviderType.AZURE_KEYVAULT
            )
        )
    }
}
