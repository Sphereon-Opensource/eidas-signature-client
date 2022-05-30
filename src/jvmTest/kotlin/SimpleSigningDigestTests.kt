import com.sphereon.vdx.ades.SigningException
import com.sphereon.vdx.ades.enums.DigestAlg
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.model.SignInput
import com.sphereon.vdx.ades.model.serializers
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.apache.commons.codec.binary.Hex
import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith

class SimpleSigningDigestTests : AbstractAdESTest() {

    @Test
    fun `Given an input with signmode DIGEST but without a digest algorithm the digest function should throw an exception`() {
        val digestInput = SignInput(input = "test".toByteArray(), signMode = SignMode.DIGEST, digestAlgorithm = null)
        val ex = assertFailsWith<SigningException> {
            constructKeySignatureService(keystoreFilename = "user_a_rsa.p12", password = "password").digest(digestInput)
        }
        assert("Cannot create a digest" in ex.message!!)
    }

    @Test
    fun `Given an input with signmode DIGEST with a digest algorithm of NONE the digest function should throw an exception`() {
        val digestInput = SignInput(input = "test".toByteArray(), signMode = SignMode.DIGEST, digestAlgorithm = DigestAlg.NONE)
        val ex = assertFailsWith<SigningException> {
            constructKeySignatureService(keystoreFilename = "user_a_rsa.p12", password = "password").digest(digestInput)
        }
        assert("Cannot create a digest" in ex.message!!)
    }

    @Test
    fun `Given an input with signmode DIGEST and several digest algorithms the digest function should return the proper digests`() {

        assertContentEquals(
            Hex.decodeHex("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
            constructKeySignatureService(keystoreFilename = "user_a_rsa.p12", password = "password").digest(
                SignInput(
                    input = "test".toByteArray(),
                    signMode = SignMode.DIGEST,
                    digestAlgorithm = DigestAlg.SHA256
                )
            ).input
        )

        println(
            Json { prettyPrint = true; serializersModule = serializers }.encodeToString(
                constructKeySignatureService(keystoreFilename = "user_a_rsa.p12", password = "password").digest(
                    SignInput(
                        input = "test".toByteArray(),
                        signMode = SignMode.DIGEST,
                        digestAlgorithm = DigestAlg.SHA256
                    )
                )
            )
        )

        assertContentEquals(
            Hex.decodeHex("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"),
            constructKeySignatureService(keystoreFilename = "user_a_rsa.p12", password = "password").digest(
                SignInput(
                    input = "test".toByteArray(),
                    signMode = SignMode.DIGEST,
                    digestAlgorithm = DigestAlg.SHA512
                )
            ).input
        )

        assertContentEquals(
            Hex.decodeHex("36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80"),
            constructKeySignatureService(keystoreFilename = "user_a_rsa.p12", password = "password").digest(
                SignInput(
                    input = "test".toByteArray(),
                    signMode = SignMode.DIGEST,
                    digestAlgorithm = DigestAlg.SHA3_256
                )
            ).input
        )

        assertContentEquals(
            Hex.decodeHex("9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14"),
            constructKeySignatureService(keystoreFilename = "user_a_rsa.p12", password = "password").digest(
                SignInput(
                    input = "test".toByteArray(),
                    signMode = SignMode.DIGEST,
                    digestAlgorithm = DigestAlg.SHA3_512
                )
            ).input
        )
    }


}
