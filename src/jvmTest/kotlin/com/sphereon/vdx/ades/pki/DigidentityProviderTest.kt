package com.sphereon.vdx.ades.pki

import AbstractAdESTest
import com.sphereon.vdx.ades.enums.*
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.pki.digidentity.DigidentityCredentialMode
import com.sphereon.vdx.ades.pki.digidentity.DigidentityCredentialOpts
import com.sphereon.vdx.ades.pki.digidentity.DigidentityProviderConfig
import com.sphereon.vdx.ades.pki.digidentity.DigidentitySecretCredentialOpts
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

class DigidentityProviderTest : AbstractAdESTest() {
    @Test
    fun `Given a KID the Azure Keyvault Certificate Provider Service should return a key`() {
        val keyProvider = KeyProviderServiceFactory.createFromConfig(constructCertificateProviderSettings(true)) {
            digidentityProviderConfig = constructProviderConfig()
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



    @Test
    fun `PAdES - Given an input with signmode DOCUMENT and DIGEST the sign method should sign the document `() {
        val pdfDocInput = this::class.java.classLoader.getResource("test-unsigned.pdf")
        val logo = this::class.java.classLoader.getResource("logo.png")
        val pdfData = OrigData(value = pdfDocInput.readBytes(), name = "test-unsigned.pdf")
        val logoData = OrigData(value = logo.readBytes(), name = "sphereon.png", mimeType = "image/png")


        val keyProvider = KeyProviderServiceFactory.createFromConfig(constructCertificateProviderSettings(true)) {
            digidentityProviderConfig = constructProviderConfig()
        }
        val signingService = KidSignatureService(keyProvider)
        val kid = "9b2b85df-9149-4440-a7a7-67953a38b832"
        val signatureConfiguration = SignatureConfiguration(

            signatureParameters = SignatureParameters(
                signaturePackaging = SignaturePackaging.ENVELOPED,
                digestAlgorithm = DigestAlg.SHA256,
                encryptionAlgorithm = CryptoAlg.RSA,
                signatureAlgorithm = SignatureAlg.RSA_SHA256,
                signatureLevelParameters = SignatureLevelParameters(
                    signatureLevel = SignatureLevel.PAdES_BASELINE_LT, bLevelParameters = BLevelParams(
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
        val signatureData = signingService.createSignature(signInput, SignatureAlg.RSA_SHA256)
        assertNotNull(signatureData)
        assertEquals(SignMode.DOCUMENT, signatureData.signMode)
        assertEquals(SignatureAlg.RSA_SHA256, signatureData.algorithm)

        // Let's create a digest ourselves and sign that as well
        val digestInput = signingService.digest(signInput)
        val signatureDigest = signingService.createSignature(digestInput, SignatureAlg.RSA_SHA256)
        assertNotNull(signatureDigest)
        assertEquals(SignMode.DIGEST, signatureDigest.signMode)
        assertEquals(SignatureAlg.RSA_SHA256, signatureDigest.algorithm)

        assertContentEquals(signatureData.value, signatureDigest.value)
        assertEquals(signatureData.keyEntry.certificate!!.fingerPrint, signatureDigest.keyEntry.certificate!!.fingerPrint)
        assertEquals(signatureData.keyEntry.certificateChain!![2].fingerPrint, signatureDigest.keyEntry.certificateChain!![2].fingerPrint)

        val signOutputData = signingService.sign(pdfData, signatureData, signatureConfiguration)
        assertNotNull(signOutputData)

        val signOutputDigest = signingService.sign(pdfData, signatureDigest, signatureConfiguration)
        assertNotNull(signOutputDigest)


        InMemoryDocument(signOutputDigest.value, signOutputData.name).save("" + System.currentTimeMillis() + "-sphereon-signed.pdf")

        val validSignatureData = signingService.isValidSignature(signInput, signatureData)
        assertTrue(validSignatureData)

        val validSignatureDigest = signingService.isValidSignature(digestInput, signatureDigest)
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

        val origDoc = documentValidator.getOriginalDocuments(documentValidator.signatures.first()).first()
        ByteArrayOutputStream().use { baos ->
            origDoc.writeTo(baos)
            assertContentEquals(pdfData.value, baos.toByteArray())
        }

        val certVerifier = CommonCertificateVerifier()

        // Create an instance of a trusted certificate source
        val trustedCertSource = CommonTrustedCertificateSource()
        // Include the chain, but not the signing cert itself
        signatureDigest.keyEntry.certificateChain!!.subList(1, 3).map { trustedCertSource.addCertificate(
            CertificateToken(it.toX509Certificate())
        ) }
        // Add trust anchors (trusted list, keystore,...) to a list of trusted certificate sources
        certVerifier.addTrustedCertSources(trustedCertSource)
        documentValidator.setCertificateVerifier(certVerifier)

        assertEquals(1, documentValidator.signatures.size)

        /*val diagData = documentValidator.diagnosticData FIXME offlineCertificateVerifier cannot be null!
        assertEquals(1, diagData.signatures.size)
        assertEquals(7, diagData.usedCertificates.size)*/

        assertContentEquals(signatureDigest.value, documentValidator.signatures.first().signatureValue)

    }

    @Test
    fun `PKCS7 - Given an input with signmode DOCUMENT and DIGEST the sign method should sign the document `() {
        val pdfDocInput = this::class.java.classLoader.getResource("test-unsigned.pdf")
        val logo = this::class.java.classLoader.getResource("logo.png")
        val pdfData = OrigData(value = pdfDocInput.readBytes(), name = "test-unsigned.pdf")
        val logoData = OrigData(value = logo.readBytes(), name = "sphereon.png", mimeType = "image/png")


        val keyProvider = KeyProviderServiceFactory.createFromConfig(constructCertificateProviderSettings(false)) {
            digidentityProviderConfig = constructProviderConfig()
        }
        val signingService = KidSignatureService(keyProvider)
        val kid = "9b2b85df-9149-4440-a7a7-67953a38b832"
        val signatureConfiguration = SignatureConfiguration(

            signatureParameters = SignatureParameters(
                signaturePackaging = SignaturePackaging.ENVELOPED,
                digestAlgorithm = DigestAlg.SHA256,
                encryptionAlgorithm = CryptoAlg.RSA,
                signatureAlgorithm = SignatureAlg.RSA_SHA256,
                signatureLevelParameters = SignatureLevelParameters(
                    signatureLevel = SignatureLevel.PKCS7_LT, bLevelParameters = BLevelParams(
//                        signingDate = Instant.parse(SIGDATE)
                    )
                ),
                signatureFormParameters = SignatureFormParameters(
                    pkcs7SignatureFormParameters = Pkcs7SignatureFormParameters(
                        mode = PdfSignatureMode.CERTIFICATION,
                        signerName = "Test Case",
                        contactInfo = "support@sphereon.com",
                        reason = "Test",
                        location = "Online",
                        signatureSize = 15000, // FIXME, this value gets lost somehow
                        signatureSubFilter = PdfSignatureSubFilter.ADBE_PKCS7_DETACHED.specName,
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
        val signatureData = signingService.createSignature(signInput, SignatureAlg.RSA_SHA256)
        assertNotNull(signatureData)
        assertEquals(SignMode.DOCUMENT, signatureData.signMode)
        assertEquals(SignatureAlg.RSA_SHA256, signatureData.algorithm)

        // Let's create a digest ourselves and sign that as well
        val digestInput = signingService.digest(signInput)
        val signatureDigest = signingService.createSignature(digestInput, SignatureAlg.RSA_SHA256)
        assertNotNull(signatureDigest)
        assertEquals(SignMode.DIGEST, signatureDigest.signMode)
        assertEquals(SignatureAlg.RSA_RAW, signatureDigest.algorithm)

        assertContentEquals(signatureData.value, signatureDigest.value)
        assertEquals(signatureData.keyEntry.certificate!!.fingerPrint, signatureDigest.keyEntry.certificate!!.fingerPrint)
        assertEquals(signatureData.keyEntry.certificateChain!![2].fingerPrint, signatureDigest.keyEntry.certificateChain!![2].fingerPrint)

        val signOutputData = signingService.sign(pdfData, signatureData, signatureConfiguration)
        assertNotNull(signOutputData)

        val signOutputDigest = signingService.sign(pdfData, signatureDigest, signatureConfiguration)
        assertNotNull(signOutputDigest)


        InMemoryDocument(signOutputDigest.value, signOutputData.name).save("" + System.currentTimeMillis() + "-sphereon-signed.pdf")

        val validSignatureData = signingService.isValidSignature(signInput, signatureData)
        assertTrue(validSignatureData)

        val validSignatureDigest = signingService.isValidSignature(digestInput, signatureDigest)
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

        val origDoc = documentValidator.getOriginalDocuments(documentValidator.signatures.first()).first()
        ByteArrayOutputStream().use { baos ->
            origDoc.writeTo(baos)
            assertContentEquals(pdfData.value, baos.toByteArray())
        }

        val certVerifier = CommonCertificateVerifier()

        // Create an instance of a trusted certificate source
        val trustedCertSource = CommonTrustedCertificateSource()
        // Include the chain, but not the signing cert itself
        signatureDigest.keyEntry.certificateChain!!.subList(1, 3).map { trustedCertSource.addCertificate(
            CertificateToken(it.toX509Certificate())
        ) }
        // Add trust anchors (trusted list, keystore,...) to a list of trusted certificate sources
        certVerifier.addTrustedCertSources(trustedCertSource)
        documentValidator.setCertificateVerifier(certVerifier)

        assertEquals(1, documentValidator.signatures.size)

        val diagData = documentValidator.diagnosticData
        assertEquals(1, diagData.signatures.size)
        assertEquals(7, diagData.usedCertificates.size)


        assertContentEquals(signatureDigest.value, documentValidator.signatures.first().signatureValue)

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
