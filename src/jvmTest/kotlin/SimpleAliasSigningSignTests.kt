import com.sphereon.vdx.ades.enums.DigestAlg
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.enums.SignatureAlg
import com.sphereon.vdx.ades.model.SignInput
import org.apache.commons.codec.binary.Hex
import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

private const val CERTIFICATE = "certificate"

class SimpleAliasSigningSignTests : AbstractAdESTest() {

    @Test
    fun `Given an input with signmode DOCUMENT the sign method should sign the document`() {
        val signInput = SignInput(input = "test".toByteArray(), signMode = SignMode.DOCUMENT, digestAlgorithm = DigestAlg.SHA256)

        val signingService = constructAliasSignatureService(enableCache = true)
        val keyEntry = signingService.certificateProvider.getKey(CERTIFICATE)!!
        val signature = signingService.createSignature(signInput, CERTIFICATE)
        assertNotNull(signature)
        assertEquals(SignatureAlg.RSA_SHA256, signature.algorithm)
        assertContentEquals(
            Hex.decodeHex("a9df413962b569f85cd5d32b44cdc0c16f8dc0b5a65a27e44faa7be302c64536b43cf663474ba3767da5a101c4ecbdc00bc95d84c1007b1213a19b94fadaf903109dcb5e70a19880d088d23c33fc4d71bc053071f34ed231f42e0f25ac12977dcbb9690f9e8fabc8c8cafdf4b12312f7e3869380955014f8781ef4c320e5c40f504ef962d4466f980652190ab4da53e0bd1181b0cbe741e22b2f83c7788b97a1d75742949631d744d847669f9c20317d698e518f1f0c9b2108e534ba08d1b952907fee51cf27226c81e0aaaffaf37a66ab4eebadd6be7579891c8653b734166315a5207645bd0ae6b5ef791bfd7acb77d8aa5479eeff66295e971432e5cecd90"),
            signature.value
        )

        assertTrue(signingService.isValidSignature(signInput, signature, keyEntry.certificate))

    }

    @Test
    fun `Given an input with signmode DIGEST the sign method should sign the document`() {
//        println(Hex.encodeHexString(MessageDigest.getInstance("SHA-256").digest("test".toByteArray())))
        val signInput = SignInput(
            input = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".toByteArray(),
            signMode = SignMode.DIGEST,
            digestAlgorithm = DigestAlg.SHA256
        )

        val signingService = constructAliasSignatureService(enableCache = true)
        val keyEntry = signingService.certificateProvider.getKey(CERTIFICATE)!!
        assertNotNull(keyEntry)
        val signature = signingService.createSignature(signInput, CERTIFICATE)
        assertNotNull(signature)
        assertEquals(SignatureAlg.RSA_SHA256, signature.algorithm)
        assertContentEquals(
            Hex.decodeHex("232a30e81b52e3520faad55f9ac57ea0160fc150e140f0f4a451a3512e7bdb0d2e7f8ea9270868c32d1af387cb49bea8317540c0031e436eb70b09d747123e5f869e89eecac780d36e6db24a452b6f7fa66bd85884d491d0bd09406aa1dd3f5ccd24a05fa38b1d3fc7d7b68c7b7a3d8fa944b644139856c756b55e3cd9b8a40b4b01cb442a1d4aaadd1a1cbdf7b2957697e59c39e336d4f0a486683787348405d0b000e0c6d13c0336c6b29f6d1dc9e29e66ae6faa54604b28a1a8c15f91b7241545ceed6ca7ecd128b931f727bb38dd7bbf999f4a65df6302dcf5c9074ca565e6490da3d3c9589f569a3a9d3a87032ed31bf009305b7963bf738c7a3d7c89db"),
            signature.value
        )

        assertTrue(signingService.isValidSignature(signInput, signature, CERTIFICATE))
    }

    @Test
    fun `Given an input with signmode DOCUMENT and maskgen function 1 the sign method should sign the document`() {
        val signInput = SignInput(input = "test".toByteArray(), signMode = SignMode.DOCUMENT, digestAlgorithm = DigestAlg.SHA256)

        val signingService = constructAliasSignatureService(enableCache = false)
        val keyEntry = signingService.certificateProvider.getKey(CERTIFICATE)!!
        val signature = signingService.createSignature(signInput, CERTIFICATE, MaskGenFunction.MGF1)
        assertNotNull(signature)
        assertEquals(SignatureAlg.RSA_SSA_PSS_SHA256_MGF1, signature.algorithm)
        // Since we use a MGF1 in this test, the signature is randomized
        assertNotNull(signature.value)

        assertTrue(signingService.isValidSignature(signInput, signature, keyEntry.certificate))

    }

    @Test
    fun `Given an input with signmode DIGEST and maskgen function 1 the sign method should sign the document`() {
//        println(Hex.encodeHexString(MessageDigest.getInstance("SHA-256").digest("test".toByteArray())))
        val signInput = SignInput(
            input = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".toByteArray(),
            signMode = SignMode.DIGEST,
            digestAlgorithm = DigestAlg.SHA256
        )

        val signingService = constructAliasSignatureService(enableCache = false)
        val keyEntry = signingService.certificateProvider.getKey(CERTIFICATE)!!
        assertNotNull(keyEntry)
        val signature = signingService.createSignature(signInput, CERTIFICATE, MaskGenFunction.MGF1)
        assertNotNull(signature)
        assertEquals(SignatureAlg.RSA_SSA_PSS_SHA256_MGF1, signature.algorithm)
        // Since we use a MGF1 in this test, the signature is randomized
        assertNotNull(signature.value)


        assertTrue(signingService.isValidSignature(signInput, signature, CERTIFICATE))
    }
}
