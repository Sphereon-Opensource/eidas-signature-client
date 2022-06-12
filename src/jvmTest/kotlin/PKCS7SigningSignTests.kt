import com.sphereon.vdx.ades.enums.*
import com.sphereon.vdx.ades.model.*
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.validation.CommonCertificateVerifier
import eu.europa.esig.dss.validation.SignedDocumentValidator
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.FileOutputStream
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

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
                        location = "Online"
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

        println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(signInput))

        val digestInput = signingService.digest(signInput)
        println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(digestInput))

        val signature = signingService.createSignature(digestInput, keyEntry)
        println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(signature))

        val signOutput = signingService.sign(origData, signature, signatureConfiguration)
        println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(signOutput))
        assertNotNull(signOutput)


        assertTrue(signingService.isValidSignature(digestInput, signature, signature.keyEntry))

        val documentValidator = SignedDocumentValidator.fromDocument(InMemoryDocument(signOutput.value, signOutput.name))
        documentValidator.setCertificateVerifier(CommonCertificateVerifier())
        val validateDocument = documentValidator.validateDocument()

        FileOutputStream("C:\\temp\\${signOutput.name}").use { fos -> // TODO remove
            fos.write(signOutput.value)
        }

        assertEquals(1, documentValidator.signatures.size)
        val diagData = documentValidator.diagnosticData
        assertEquals(1, diagData.signatures.size)
        assertEquals(3, diagData.usedCertificates.size)

        assertContentEquals(signature.value, documentValidator.signatures.first().signatureValue)
        val origDoc = documentValidator.getOriginalDocuments(documentValidator.signatures.first()).first()
        ByteArrayOutputStream().use { baos ->
            origDoc.writeTo(baos)
            assertContentEquals(origData.value, baos.toByteArray())
        }
    }

}
