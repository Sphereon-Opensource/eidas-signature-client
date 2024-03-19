package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.enums.CryptoAlg
import com.sphereon.vdx.ades.enums.DigestAlg
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.enums.SignatureAlg
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.Key
import com.sphereon.vdx.ades.model.KeyProviderSettings
import com.sphereon.vdx.ades.model.SignInput
import com.sphereon.vdx.ades.model.Signature
import com.sphereon.vdx.ades.sign.util.toDSS
import com.sphereon.vdx.ades.sign.util.toJavaPublicKey
import eu.europa.esig.dss.enumerations.SignatureAlgorithm
import eu.europa.esig.dss.spi.DSSSecurityProvider
import mu.KotlinLogging
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.DigestInfo
import java.security.GeneralSecurityException
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.*


private val logger = KotlinLogging.logger {}

/**
 * This is a base class for Key Providers
 */
abstract class AbstractKeyProviderService(
    override val settings: KeyProviderSettings,
) : IKeyProviderService {

    @Suppress("LeakingThis")
    protected val cacheService: CacheService<String, IKeyEntry> =
        CacheService("Keys", settings.config.cacheEnabled, settings.config.cacheTTLInSeconds)


    override fun createSignature(signInput: SignInput, keyEntry: IKeyEntry): Signature {
        return createSignatureImpl(signInput, keyEntry, null)
    }

    override fun createSignature(signInput: SignInput, keyEntry: IKeyEntry, mgf: MaskGenFunction): Signature {
        return createSignatureImpl(signInput, keyEntry, mgf)
    }

    override fun createSignature(signInput: SignInput, keyEntry: IKeyEntry, signatureAlgorithm: SignatureAlg): Signature {
        val input = signInput.copy(digestAlgorithm = signatureAlgorithm.digestAlgorithm)
        return createSignatureImpl(input, keyEntry, signatureAlgorithm.maskGenFunction)
    }

    override fun isValidSignature(signInput: SignInput, signature: Signature, keyEntry: IKeyEntry): Boolean {
        return isValidSignature(signInput, signature, keyEntry.publicKey)
    }

    override fun isValidSignature(signInput: SignInput, signature: Signature, publicKey: Key): Boolean {
        logger.entry(signInput, signature, publicKey)
        Objects.requireNonNull(signInput, "signInput cannot be null!")
        Objects.requireNonNull(signature, "Signature cannot be null!")
        Objects.requireNonNull(publicKey, "Public key cannot be null!")
        return try {
            val javaSig = java.security.Signature.getInstance(
                // Replace with RAW for RSA in case we receive a digest. Probably we should correct the signature algorithm value itself instead of correcting it here
                if (signInput.signMode == SignMode.DIGEST && signature.algorithm.encryptionAlgorithm == CryptoAlg.RSA)
                    if (signature.algorithm.maskGenFunction == null) SignatureAlgorithm.RSA_RAW.jceId else SignatureAlgorithm.RSA_SSA_PSS_RAW_MGF1.jceId
                else signature.algorithm.toDSS().jceId,
                DSSSecurityProvider.getSecurityProviderName()
            )

            if (signature.algorithm.maskGenFunction != null) {
                val digestJavaName: String = signature.algorithm.digestAlgorithm?.toDSS()!!.javaName
                val parameterSpec = PSSParameterSpec(
                    digestJavaName,
                    "MGF1",
                    MGF1ParameterSpec(digestJavaName),
                    signature.algorithm.digestAlgorithm.toDSS().saltLength,
                    1
                )
                javaSig.setParameter(parameterSpec)
            }

            javaSig.initVerify(publicKey.toJavaPublicKey())
            if (signInput.signMode == SignMode.DIGEST && signature.algorithm.digestAlgorithm != null) {
                javaSig.update(derEncode(signature.algorithm.digestAlgorithm, signInput))
            } else {
                javaSig.update(signInput.input)
            }
            val verify = javaSig.verify(signature.value)
            logger.info { "Signature with date '${signature.date}' and provider '${signature.providerId}' for input '${signInput.name}' was ${if (verify) "VALID" else "INVALID"}" }
            logger.exit(verify)

        } catch (e: GeneralSecurityException) {
            logger.warn { "Signature with date '${signature.date}' and provider '${signature.providerId}' for input '${signInput.name}' was INVALID, with an exception: ${e.message}" }
            false
        }
    }

    /*
       When we have predigested value instead the content that has yet to be digested, we need to make sure
       we DER encode the hash because in RSA_RAW / NONEwithRSA mode BouncyCastle will no longer take care of this,
       hence the verification will fail.
     */
    private fun derEncode(
        digestAlgorithm: DigestAlg,
        signInput: SignInput
    ): ByteArray {
        val asN1ObjectIdentifier = ASN1ObjectIdentifier(digestAlgorithm.oid)
        val algId = AlgorithmIdentifier(asN1ObjectIdentifier, DERNull.INSTANCE)
        val dInfo = DigestInfo(algId, signInput.input)
        return dInfo.getEncoded("DER")
    }

    protected abstract fun createSignatureImpl(
        signInput: SignInput,
        keyEntry: IKeyEntry,
        mgf: MaskGenFunction? = null
    ): Signature

    protected fun isDigestMode(signInput: SignInput) =
        signInput.signMode == SignMode.DIGEST && signInput.digestAlgorithm != DigestAlg.NONE
}
