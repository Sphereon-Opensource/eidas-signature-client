package com.sphereon.vdx.ades.sign

import com.sphereon.vdx.ades.SigningException
import com.sphereon.vdx.ades.enums.*
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.pki.ICertificateProviderService
import com.sphereon.vdx.ades.sign.util.*
import com.sphereon.vdx.pkcs7.PKCS7SignatureParameters
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


open class KeySignatureService(val certificateProvider: ICertificateProviderService) : IKeySignatureService {

    override fun digest(signInput: SignInput): SignInput {
//        if (signInput.signMode == SignMode.DIGEST) throw SigningException("Signing mode must be DOCUMENT when creating a digest!")
        if (signInput.digestAlgorithm == null) throw SigningException("Cannot create a digest when the digest mode is not specified")
        if (signInput.digestAlgorithm == DigestAlg.NONE) throw SigningException("Cannot create a digest when the digest mode is set to NONE")
        val digest = DSSUtils.digest(signInput.digestAlgorithm.toDSS(), signInput.input)
        return SignInput(digest, SignMode.DIGEST, signInput.digestAlgorithm, signInput.name)
    }

    override fun createSignature(signInput: SignInput, keyEntry: IKeyEntry): Signature {
        return certificateProvider.createSignature(signInput, keyEntry)
    }

    override fun createSignature(signInput: SignInput, keyEntry: IKeyEntry, mgf: MaskGenFunction): Signature {
        return certificateProvider.createSignature(signInput, keyEntry, mgf)
    }

    override fun createSignature(signInput: SignInput, keyEntry: IKeyEntry, signatureAlgorithm: SignatureAlg): Signature {
        return certificateProvider.createSignature(signInput, keyEntry, signatureAlgorithm)
    }

    override fun isValidSignature(signInput: SignInput, signature: Signature, keyEntry: IKeyEntry): Boolean {
        return certificateProvider.isValidSignature(signInput, signature, keyEntry)
    }


    override fun isValidSignature(signInput: SignInput, signature: Signature, publicKey: Key): Boolean {
        return certificateProvider.isValidSignature(signInput, signature, publicKey)
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
            SignatureForm.PKCS7 -> adESService.toPKCS7Service().getDataToSign(toSign, signatureParameters as PKCS7SignatureParameters)
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
            SignatureForm.PKCS7 -> adESService.toPKCS7Service()
                .signDocument(toSign, signatureParameters as PKCS7SignatureParameters, signature.toDSS())
            else -> throw SigningException("Signing using signature form ${signatureConfiguration.signatureParameters.signatureForm()} not support")
        }

        dssDocument.save("" + System.currentTimeMillis() + "-" + dssDocument.name)
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



}
