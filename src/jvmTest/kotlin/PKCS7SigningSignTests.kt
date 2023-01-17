import com.sphereon.vdx.ades.enums.CryptoAlg
import com.sphereon.vdx.ades.enums.DigestAlg
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.enums.SignatureAlg
import com.sphereon.vdx.ades.enums.SignatureLevel
import com.sphereon.vdx.ades.enums.SignaturePackaging
import com.sphereon.vdx.ades.model.OrigData
import com.sphereon.vdx.ades.model.PdfSignatureMode
import com.sphereon.vdx.ades.model.Pkcs7SignatureFormParameters
import com.sphereon.vdx.ades.model.SignatureConfiguration
import com.sphereon.vdx.ades.model.SignatureFormParameters
import com.sphereon.vdx.ades.model.SignatureLevelParameters
import com.sphereon.vdx.ades.model.SignatureParameters
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.validation.CommonCertificateVerifier
import eu.europa.esig.dss.validation.SignedDocumentValidator
import org.junit.jupiter.api.Test
import java.io.FileOutputStream
import kotlin.test.assertNotNull

class PKCS7SigningSignTests : AbstractAdESTest() {

    @Test
    fun `Given an input with signmode DOCUMENT the sign method should sign the document`() {
        val pdfDocInput = this::class.java.classLoader.getResource("test-unsigned.pdf")
        val origData = OrigData(value = pdfDocInput.readBytes(), name = "test-unsigned.pdf")

        val signingService = constructKeySignatureService(keystoreFilename = "good-user.p12", password = "ks-password")
        val keyEntry = signingService.keyProvider.getKey("good-user")!!
        val signatureConfiguration = SignatureConfiguration(

            signatureParameters = SignatureParameters(
                signaturePackaging = SignaturePackaging.ENVELOPED,
                digestAlgorithm = DigestAlg.SHA256,
                encryptionAlgorithm = CryptoAlg.RSA,
                signatureAlgorithm = SignatureAlg.RSA_SHA256,
                signatureLevelParameters = SignatureLevelParameters(
                    signatureLevel = SignatureLevel.PKCS7_B,
                ),
                signatureFormParameters = SignatureFormParameters(
                    pkcs7SignatureFormParameters = Pkcs7SignatureFormParameters(
                        signerName = "Test Case",
                        contactInfo = "support@sphereon.com",
                        reason = "Test",
                        location = "Online",
                        mode = PdfSignatureMode.CERTIFICATION
                    )
                )
            ),
        )
        val signInput = signingService.determineSignInput(
            origData = origData,
            keyEntry = keyEntry,
            signMode = SignMode.DOCUMENT,
            signatureConfiguration = signatureConfiguration
        )

//        println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(signInput))

        val digestInput = signingService.digest(signInput)
//        println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(digestInput))

        val signature = signingService.createSignature(digestInput, keyEntry)
//        println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(signature))

        val signOutput = signingService.sign(origData, keyEntry, SignMode.DOCUMENT, signatureConfiguration)
//        println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(signOutput))
            assertNotNull(signOutput)

            FileOutputStream(signOutput.name!!).use {
                it.write(signOutput.value)
        }


        //assertTrue(signingService.isValidSignature(digestInput, signature, keyEntry))
//        assertTrue(signingService.isValidSignature(signInput, signature, signature.keyEntry.publicKey!!))
      /*  val documentValidator = SignedDocumentValidator.fromDocument(InMemoryDocument(signOutput.value, signOutput.name))
        documentValidator.setCertificateVerifier(CommonCertificateVerifier())

        assertEquals(1, documentValidator.signatures.size)
        val diagData = documentValidator.diagnosticData
        assertEquals(1, diagData.signatures.size)
        assertEquals(3, diagData.usedCertificates.size)

        //assertContentEquals(signature.value, documentValidator.signatures.first().signatureValue)
        val origDoc = documentValidator.getOriginalDocuments(documentValidator.signatures.first()).first()
        ByteArrayOutputStream().use { baos ->
            origDoc.writeTo(baos)
            assertContentEquals(origData.value, baos.toByteArray())
        }
*/
    }

    @Test
    fun `Given an input with signmode DOCUMENT the simpleSign method should sign the document`() {
        val pdfDocInput = this::class.java.classLoader.getResource("test-unsigned.pdf")
        val origData = OrigData(value = pdfDocInput.readBytes(), name = "test-unsigned.pdf")

        val signingService = constructKeySignatureService(keystoreFilename = "good-user.p12", password = "ks-password")
        val keyEntry = signingService.keyProvider.getKey("good-user")!!
        val signatureConfiguration = SignatureConfiguration(

            signatureParameters = SignatureParameters(
                signaturePackaging = SignaturePackaging.ENVELOPED,
                digestAlgorithm = DigestAlg.SHA256,
                encryptionAlgorithm = CryptoAlg.RSA,
                signatureAlgorithm = SignatureAlg.RSA_SHA256,
                signatureLevelParameters = SignatureLevelParameters(
                    signatureLevel = SignatureLevel.PKCS7_B,
                ),
                signatureFormParameters = SignatureFormParameters(
                    pkcs7SignatureFormParameters = Pkcs7SignatureFormParameters(
                        signerName = "Test Case",
                        contactInfo = "support@sphereon.com",
                        reason = "Test",
                        location = "Online"
                    )
                )
            ),
        )

        val signOutput = signingService.simpleSign(origData, keyEntry, SignMode.DOCUMENT, signatureConfiguration)
        assertNotNull(signOutput)
        val documentValidator = SignedDocumentValidator.fromDocument(InMemoryDocument(signOutput.value, signOutput.name))
        documentValidator.setCertificateVerifier(CommonCertificateVerifier())

       /* assertEquals(1, documentValidator.signatures.size)
        val diagData = documentValidator.diagnosticData
        assertEquals(1, diagData.signatures.size)
        assertEquals(3, diagData.usedCertificates.size)*/
    }
}
