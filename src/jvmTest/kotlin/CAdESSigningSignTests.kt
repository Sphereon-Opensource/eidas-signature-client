import com.sphereon.vdx.ades.enums.*
import com.sphereon.vdx.ades.model.OrigData
import com.sphereon.vdx.ades.model.SignatureConfiguration
import com.sphereon.vdx.ades.model.SignatureLevelParameters
import com.sphereon.vdx.ades.model.SignatureParameters
import com.sphereon.vdx.ades.sign.KeySignatureService
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.validation.CommonCertificateVerifier
import eu.europa.esig.dss.validation.SignedDocumentValidator
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class CAdESSigningSignTests : AbstractAdESTest() {

    @Test
    fun `Given an input with signmode DOCUMENT the sign method should sign the document`() {
        val origData = OrigData(value = "test".toByteArray())

        val certProvider = constructCertProviderService()

        val signingService = KeySignatureService(certProvider)
        val keyEntry = certProvider.getKey("certificate")!!


        val signatureConfiguration = SignatureConfiguration(
            signatureParameters = SignatureParameters(
                signaturePackaging = SignaturePackaging.ENVELOPING,
                digestAlgorithm = DigestAlg.SHA256,
                encryptionAlgorithm = CryptoAlg.RSA,
                signatureAlgorithm = SignatureAlg.RSA_SHA256,
                signatureLevelParameters = SignatureLevelParameters(
                    signatureLevel = SignatureLevel.CAdES_BASELINE_B,
                    /* bLevelParameters = BLevelParams(

                     )*/
                )
            ),
        )

        val signOutputUsingKey = signingService.sign(origData, keyEntry, signMode = SignMode.DOCUMENT, signatureConfiguration)
        assertNotNull(signOutputUsingKey)

        val signInput = signingService.determineSignInput(
            origData = origData,
            keyEntry = keyEntry,
            signMode = SignMode.DOCUMENT,
            signatureConfiguration = signatureConfiguration
        )
        val signature = signingService.createSignature(signInput, keyEntry)
        val signOutputUsingSig = signingService.sign(origData, signature, signatureConfiguration)
        assertNotNull(signOutputUsingSig)

        val documentValidator = SignedDocumentValidator.fromDocument(InMemoryDocument(signOutputUsingSig.value, signOutputUsingSig.name))
        documentValidator.setCertificateVerifier(CommonCertificateVerifier())

        assertEquals(1, documentValidator.signatures.size)
        val diagData = documentValidator.diagnosticData
        assertEquals(1, diagData.signatures.size)
        assertEquals(1, diagData.usedCertificates.size)

//        File("" + System.currentTimeMillis() + "-" + signOutputUsingSig.name).writeBytes(signOutputUsingSig.value)

        assertContentEquals(signature.value, documentValidator.signatures.first().signatureValue)
        val origDoc = documentValidator.getOriginalDocuments(documentValidator.signatures.first()).first()
        ByteArrayOutputStream().use { baos ->
            origDoc.writeTo(baos)
            assertContentEquals(origData.value, baos.toByteArray())
        }

    }

}
