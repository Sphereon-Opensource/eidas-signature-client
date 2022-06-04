package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.enums.*
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.sign.util.toDSS
import com.sphereon.vdx.ades.sign.util.toJavaPublicKey
import eu.europa.esig.dss.enumerations.SignatureAlgorithm
import eu.europa.esig.dss.spi.DSSSecurityProvider
import java.security.GeneralSecurityException
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.*

abstract class AbstractCertificateProviderService(override val settings: CertificateProviderSettings) : ICertificateProviderService {
    protected val cacheService: CacheService = CacheService(settings)

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
            javaSig.update(signInput.input)
            javaSig.verify(signature.value)
        } catch (e: GeneralSecurityException) {
            println(e)
            false
        }
    }

    protected abstract fun createSignatureImpl(signInput: SignInput, keyEntry: IKeyEntry, mgf: MaskGenFunction? = null): Signature
    protected fun isDigestMode(signInput: SignInput) =
        signInput.signMode == SignMode.DIGEST && signInput.digestAlgorithm != DigestAlg.NONE
}
