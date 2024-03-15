package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.enums.*
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.sign.util.toDSS
import com.sphereon.vdx.ades.sign.util.toJavaPublicKey
import eu.europa.esig.dss.enumerations.SignatureAlgorithm
import eu.europa.esig.dss.spi.DSSSecurityProvider
import mu.KotlinLogging
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
                getSignatureAlgorithmJceId(signInput, signature),
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
            /*val digest = if (signInput.signMode == SignMode.DIGEST || signature.algorithm.digestAlgorithm == null) {
                signInput.input
            } else {
                DSSUtils.digest(signature.algorithm.digestAlgorithm.toDSS(), signInput.input)
            }*/
            javaSig.update(signInput.input)
            val verify = javaSig.verify(signature.value)
            logger.info { "Signature with date '${signature.date}' and provider '${signature.providerId}' for input '${signInput.name}' was ${if (verify) "VALID" else "INVALID"}" }
            logger.exit(verify)

        } catch (e: GeneralSecurityException) {
            logger.warn { "Signature with date '${signature.date}' and provider '${signature.providerId}' for input '${signInput.name}' was INVALID, with an exception: ${e.message}" }
            false
        }
    }

    private fun getSignatureAlgorithmJceId(signInput: SignInput, signature: Signature): String {
        if (signInput.signMode != SignMode.DIGEST || signature.algorithm.encryptionAlgorithm != CryptoAlg.RSA) {
            return signature.algorithm.toDSS().jceId
        }

        val hasMaskGenFunction = signature.algorithm.maskGenFunction
        return when (signature.algorithm.digestAlgorithm) {
            DigestAlg.SHA256 -> when (hasMaskGenFunction) {
                null -> SignatureAlgorithm.RSA_SHA256.jceId
                else -> SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1.jceId
            }
            DigestAlg.SHA3_256 -> when (hasMaskGenFunction) {
                null -> SignatureAlgorithm.RSA_SHA3_256.jceId
                else -> SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1.jceId
            }
            DigestAlg.SHA512 -> when (hasMaskGenFunction) {
                null -> SignatureAlgorithm.RSA_SHA512.jceId
                else -> SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1.jceId
            }
            DigestAlg.SHA3_512 -> when (hasMaskGenFunction) {
                null -> SignatureAlgorithm.RSA_SHA3_512.jceId
                else -> SignatureAlgorithm.RSA_SSA_PSS_SHA3_512_MGF1.jceId
            }
            else -> when (hasMaskGenFunction) {
                null -> SignatureAlgorithm.RSA_RAW.jceId
                else -> SignatureAlgorithm.RSA_SSA_PSS_RAW_MGF1.jceId
            }
        }
    }

    protected abstract fun createSignatureImpl(signInput: SignInput, keyEntry: IKeyEntry, mgf: MaskGenFunction? = null): Signature
    protected fun isDigestMode(signInput: SignInput) =
        signInput.signMode == SignMode.DIGEST && signInput.digestAlgorithm != DigestAlg.NONE
}
