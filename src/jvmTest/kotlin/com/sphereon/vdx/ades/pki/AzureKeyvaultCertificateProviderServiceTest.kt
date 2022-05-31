package com.sphereon.vdx.ades.pki

import AbstractAdESTest
import com.sphereon.vdx.ades.enums.*
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.sign.AliasSignatureService
import com.sphereon.vdx.ades.sign.util.toX509Certificate
import eu.europa.esig.dss.enumerations.DigestAlgorithm
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator
import eu.europa.esig.dss.service.crl.OnlineCRLSource
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource
import eu.europa.esig.dss.spi.x509.CommonCertificateSource
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource
import eu.europa.esig.dss.spi.x509.ListCertificateSource
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource
import eu.europa.esig.dss.validation.CommonCertificateVerifier
import eu.europa.esig.dss.validation.SignaturePolicyProvider
import eu.europa.esig.dss.validation.SignedDocumentValidator
import eu.europa.esig.dss.validation.executor.ValidationLevel
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toInstant
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue


class AzureKeyvaultCertificateProviderServiceTest : AbstractAdESTest() {

    @Test
    fun `Given an alias the Azure Keyvault Certificate Provider Service should return a key`() {
        val certProvider = CertificateProviderServiceFactory.createFromConfig(
            constructCertificateProviderSettings(false),
            azureKeyvaultClientConfig = constructKeyvaultClientConfig()
        )
        val key = certProvider.getKey("esignum:3f98a9a740fb41b79e3679cce7a34ba6")

        assertNotNull(key)
        assertEquals("esignum:3f98a9a740fb41b79e3679cce7a34ba6", key.alias)
        assertNotNull(key.publicKey)
        assertEquals("X.509", key.publicKey.format)
        assertEquals(CryptoAlg.RSA, key.publicKey.algorithm)
        assertEquals("59F815EF01229B27147BB84F2F412C16C5BD6BE0", key.certificate?.fingerPrint)
        assertEquals("CN=Ensured Document Signing CA, O=Ensured B.V., L=Heerhugowaard, ST=Noord-Holland, C=NL", key.certificate?.issuerDN)
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

        /*   assertNotNull(key.certificateChain)
           assertEquals(3, key.certificateChain!!.size)
           // We already tested a certificate above. So we only test for proper order of the cert chain here
           assertEquals("1A485229434026D47F47ADE3BDCA499253F588C0", key.certificateChain!![0].fingerPrint)
           assertEquals("9198F0B98F86315152C2B27D74112D422D111BF0", key.certificateChain!![1].fingerPrint)
           assertEquals("F013A0FD6D5B45D2DD1792879545AAB1CA6117EA", key.certificateChain!![2].fingerPrint)*/

    }

    @Test
    fun `Given an input with signmode DOCUMENT the sign method should sign the document`() {
        val pdfDocInput = this::class.java.classLoader.getResource("test-unsigned.pdf")
        val origData = OrigData(value = pdfDocInput.readBytes(), name = "test-unsigned.pdf")


        val certProvider = CertificateProviderServiceFactory.createFromConfig(
            constructCertificateProviderSettings(false),
            azureKeyvaultClientConfig = constructKeyvaultClientConfig()
        )
        val signingService = AliasSignatureService(certProvider)
        val alias = "esignum:3f98a9a740fb41b79e3679cce7a34ba6"
        val signatureConfiguration = SignatureConfiguration(

            signatureParameters = SignatureParameters(
                signaturePackaging = SignaturePackaging.ENVELOPED,
                digestAlgorithm = DigestAlg.SHA256,
                encryptionAlgorithm = CryptoAlg.RSA,
                signatureAlgorithm = SignatureAlg.RSA_SHA256,
                signatureLevelParameters = SignatureLevelParameters(
                    signatureLevel = SignatureLevel.PAdES_BASELINE_B,
                ),
                signatureFormParameters = SignatureFormParameters(
                    padesSignatureFormParameters = PadesSignatureFormParameters(
                        signerName = "Test Case",
                        contactInfo = "support@sphereon.com",
                        reason = "Test",
                        location = "Online",
//                        signatureSubFilter = "adbe.pkcs7.detached"
                    )
                )
            ),
        )
        val signInput = signingService.determineSignInput(
            origData = origData,
            alias = alias,
            signMode = SignMode.DOCUMENT,
            signatureConfiguration = signatureConfiguration
        )

        println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(signInput))

        val digestInput = signingService.digest(signInput)
        println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(digestInput))

        val signature = signingService.createSignature(digestInput, alias)
        println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(signature))

        val signOutput = signingService.sign(origData, signature, signatureConfiguration)
        println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(signOutput))
        assertNotNull(signOutput)

        val validSignature = signingService.isValidSignature(signInput, signature, alias)
        assertTrue(validSignature)

//        assertTrue(signingService.isValidSignature(digestInput, signature, signature.publicKey!!))
//        assertTrue(signingService.isValidSignature(signInput, signature, signature.certificate!!))
        val documentValidator = PDFDocumentValidator(
            InMemoryDocument(
                signOutput.value,
                signOutput.name
            )
        ) //.fromDocument(InMemoryDocument(signOutput.value, signOutput.name))
        documentValidator.setValidationLevel(ValidationLevel.BASIC_SIGNATURES)


        documentValidator.setValidationLevel(ValidationLevel.BASIC_SIGNATURES)
//        documentValidator.setSignaturePolicyProvider(SignaturePolicyProvider())
        documentValidator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_CERTIFICATES_AND_REVOCATION_DATA)
        documentValidator.setIncludeSemantics(true)
        documentValidator.setEnableEtsiValidationReport(true)

        val certVerifier = CommonCertificateVerifier()
        certVerifier.defaultDigestAlgorithm = DigestAlgorithm.SHA256
//        certVerifier.trustedCertSources = ListCertificateSource()

        // Capability to download resources from AIA
//        certVerifier.aiaSource = DefaultAIASource()

// Capability to request OCSP Responders
        certVerifier.ocspSource = OnlineOCSPSource()

// Capability to download CRL
        certVerifier.crlSource = OnlineCRLSource()

// Create an instance of a trusted certificate source
        val trustedCertSource = CommonTrustedCertificateSource()
//        trustedCertSource.addCertificate(CertificateToken(signature.certificate!!.toX509Certificate()))
        signature.certificateChain!!.map { trustedCertSource.addCertificate(CertificateToken(it.toX509Certificate())) }


// Add trust anchors (trusted list, keystore,...) to a list of trusted certificate sources
// Hint : use method {@code CertificateVerifier.setTrustedCertSources(certSources)} in order to overwrite the existing list

// Add trust anchors (trusted list, keystore,...) to a list of trusted certificate sources
// Hint : use method {@code CertificateVerifier.setTrustedCertSources(certSources)} in order to overwrite the existing list
        certVerifier.addTrustedCertSources(trustedCertSource)
        documentValidator.setCertificateVerifier(certVerifier)


        assertEquals(1, documentValidator.signatures.size)
        val validateDocument = documentValidator.validateDocument()
        val diagData = documentValidator.diagnosticData
        assertEquals(1, diagData.signatures.size)
        assertEquals(4, diagData.usedCertificates.size)

        assertContentEquals(signature.value, documentValidator.signatures.first().signatureValue)
        val origDoc = documentValidator.getOriginalDocuments(documentValidator.signatures.first()).first()
        ByteArrayOutputStream().use { baos ->
            origDoc.writeTo(baos)
            assertContentEquals(origData.value, baos.toByteArray())
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
                credentialMode = CredentialMode.SERVICE_CLIENT_SECRET,
                secretCredentialOpts = SecretCredentialOpts(
                    clientId = "d1570d88-02ff-4c98-b5e6-49eda718708f",
                    clientSecret = "_sug439PHn8745_YG-4CzcNr_CKTFLTljW",
                )
            )
        )
    }

    private fun constructCertificateProviderSettings(
        enableCache: Boolean = false
    ): CertificateProviderSettings {

        return CertificateProviderSettings(
            id = "eisgnum-test",
            config = CertificateProviderConfig(
                cacheEnabled = enableCache,
                type = CertificateProviderType.AZURE_KEYVAULT,

                )
        )
    }
}
