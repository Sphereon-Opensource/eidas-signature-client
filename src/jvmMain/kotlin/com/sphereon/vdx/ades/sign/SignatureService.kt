package com.sphereon.vdx.ades.sign

import com.sphereon.vdx.ades.SigningException
import com.sphereon.vdx.ades.enums.*
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.pki.CertificateProviderService
import com.sphereon.vdx.ades.sign.util.*
import eu.europa.esig.dss.cades.CAdESSignatureParameters
import eu.europa.esig.dss.enumerations.SignatureAlgorithm
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.model.ToBeSigned
import eu.europa.esig.dss.pades.PAdESSignatureParameters
import eu.europa.esig.dss.spi.DSSSecurityProvider
import eu.europa.esig.dss.spi.DSSUtils
import java.io.ByteArrayOutputStream
import java.security.GeneralSecurityException
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.*


open class SignatureService(override val certificateProvider: CertificateProviderService) : ISignatureService {

    // todo: We are creating another connection, do we need to expose the connection from the cert provider?
    private val tokenConnection = ConnectionFactory.connection(this.certificateProvider.settings)


    override fun digest(signInput: SignInput): SignInput {
//        if (signInput.signMode != SignMode.DIGEST) throw SigningException("Signing mode must be DIGEST when creating a digest!")
        if (signInput.digestAlgorithm == null) throw SigningException("Cannot create a digest when the digest mode is not specified")
        if (signInput.digestAlgorithm == DigestAlg.NONE) throw SigningException("Cannot create a digest when the digest mode is set to NONE")
        val digest = DSSUtils.digest(signInput.digestAlgorithm.toDSS(), signInput.input)
        return SignInput(digest, SignMode.DIGEST, signInput.digestAlgorithm, signInput.name)
    }

    override fun createSignature(signInput: SignInput, keyEntry: IKeyEntry): Signature {
        return signImpl(signInput, keyEntry, null)
    }

    override fun createSignature(signInput: SignInput, keyEntry: IKeyEntry, mgf: MaskGenFunction): Signature {
        return signImpl(signInput, keyEntry, mgf)
    }

    override fun createSignature(signInput: SignInput, keyEntry: IKeyEntry, signatureAlgorithm: SignatureAlg): Signature {
        val input = signInput.copy(digestAlgorithm = signatureAlgorithm.digestAlgorithm)
        return signImpl(input, keyEntry, signatureAlgorithm.maskGenFunction)
    }

    override fun isValidSignature(signInput: SignInput, signature: Signature, keyEntry: IKeyEntry): Boolean {
        return isValidSignature(signInput, signature, keyEntry.certificate)
    }


    override fun isValidSignature(signInput: SignInput, signature: Signature, certificate: Certificate): Boolean {
        Objects.requireNonNull(signInput, "signInput cannot be null!")
        Objects.requireNonNull(signature, "Signature cannot be null!")
        Objects.requireNonNull(certificate, "Certificate cannot be null!")
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
            javaSig.initVerify(certificate.toX509Certificate().publicKey)
            javaSig.update(signInput.input)
            javaSig.verify(signature.value)
        } catch (e: GeneralSecurityException) {
            false
        }
    }


    override fun determineSignInput(
        origData: OrigData,
        keyEntry: IKeyEntry,
        signMode: SignMode,
        signatureConfiguration: SignatureConfiguration
    ): SignInput {
        val adESService = AdESServiceFactory.getService(signatureConfiguration)
        val toSign = InMemoryDocument(origData.value, origData.name)
        val signatureParameters =
            signatureConfiguration.signatureParameters.toDSS(certificate = keyEntry.certificate, certificateChain = keyEntry.certificateChain)

        val toBeSigned = when (signatureConfiguration.signatureParameters.signatureForm()) {
            SignatureForm.CAdES -> adESService.toCAdESService().getDataToSign(toSign, signatureParameters as CAdESSignatureParameters)
            SignatureForm.PAdES -> adESService.toPAdESService().getDataToSign(toSign, signatureParameters as PAdESSignatureParameters)
            SignatureForm.DIGEST -> ToBeSigned(origData.value)
            else -> throw SigningException("Determining sign input using signature form ${signatureConfiguration.signatureParameters.signatureForm()} not support")
        }
        return SignInput(
            input = toBeSigned.bytes,
            name = origData.name,
            signMode = signMode,
            digestAlgorithm = signatureConfiguration.signatureParameters.digestAlgorithm
        )
    }

    override fun sign(origData: OrigData, keyEntry: IKeyEntry, signMode: SignMode, signatureConfiguration: SignatureConfiguration): SignOutput {
        val signInput = determineSignInput(origData, keyEntry, signMode, signatureConfiguration)
        return sign(origData, this.createSignature(signInput, keyEntry), signatureConfiguration)
    }

    override fun sign(origData: OrigData, signature: Signature, signatureConfiguration: SignatureConfiguration): SignOutput {
        val adESService = AdESServiceFactory.getService(signatureConfiguration)
        val signatureParameters =
            signatureConfiguration.signatureParameters.toDSS(certificate = signature.certificate, certificateChain = signature.certificateChain)

        val toSign = InMemoryDocument(origData.value, origData.name)
        val dssDocument = when (signatureConfiguration.signatureParameters.signatureForm()) {
            SignatureForm.CAdES -> adESService.toCAdESService()
                .signDocument(toSign, signatureParameters as CAdESSignatureParameters, signature.toDSS())
            SignatureForm.PAdES -> adESService.toPAdESService()
                .signDocument(toSign, signatureParameters as PAdESSignatureParameters, signature.toDSS())
            else -> throw SigningException("Signing using signature form ${signatureConfiguration.signatureParameters.signatureForm()} not support")
        }

//        dssDocument.save("" + System.currentTimeMillis() + "-" + dssDocument.name)
        ByteArrayOutputStream().use { baos ->

            dssDocument.writeTo(baos)
            return SignOutput(
                value = baos.toByteArray(),
                signature = signature,
                mimeType = dssDocument.mimeType?.mimeTypeString,
                signMode = signature.signMode,
                digestAlgorithm = signature.algorithm.digestAlgorithm ?: signatureConfiguration.signatureParameters.digestAlgorithm,
                name = dssDocument.name
            )
        }

    }

    /* protected fun digestWhenNeeded(signInput: SignInput): SignInput {
         // todo: We need to create a deepcopy method for the input, as the copy is shallow
         return if (signInput.signMode == SignMode.DIGEST) digest(signInput) else signInput.copy()
     }*/

    protected fun signImpl(signInput: SignInput, keyEntry: IKeyEntry, mgf: MaskGenFunction? = null): Signature {
        if (signInput.digestAlgorithm == null) throw SigningException("Digest algorithm needs to be specified at this point")

        return if (signInput.signMode == SignMode.DIGEST && signInput.digestAlgorithm != DigestAlg.NONE) {
            tokenConnection.signDigest(signInput.toDigest(), mgf?.toDSS(), keyEntry.toDSS()).fromDSS(signMode = signInput.signMode, keyEntry)
        } else {
            tokenConnection.sign(signInput.toBeSigned(), signInput.digestAlgorithm.toDSS(), mgf?.toDSS(), keyEntry.toDSS())
                .fromDSS(signMode = signInput.signMode, keyEntry)
        }
    }

}
