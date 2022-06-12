package com.sphereon.vdx.ades.sign

import com.sphereon.vdx.ades.SigningException
import com.sphereon.vdx.ades.enums.DigestAlg
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.enums.SignatureAlg
import com.sphereon.vdx.ades.enums.SignatureForm
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.Key
import com.sphereon.vdx.ades.model.OrigData
import com.sphereon.vdx.ades.model.SignInput
import com.sphereon.vdx.ades.model.SignOutput
import com.sphereon.vdx.ades.model.Signature
import com.sphereon.vdx.ades.model.SignatureConfiguration
import com.sphereon.vdx.ades.pki.IKeyProviderService
import com.sphereon.vdx.ades.sign.util.AdESServiceFactory
import com.sphereon.vdx.ades.sign.util.signatureForm
import com.sphereon.vdx.ades.sign.util.toCAdESService
import com.sphereon.vdx.ades.sign.util.toDSS
import com.sphereon.vdx.ades.sign.util.toPAdESService
import com.sphereon.vdx.ades.sign.util.toPKCS7Service
import com.sphereon.vdx.pkcs7.PKCS7SignatureParameters
import eu.europa.esig.dss.cades.CAdESSignatureParameters
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.model.ToBeSigned
import eu.europa.esig.dss.pades.PAdESSignatureParameters
import eu.europa.esig.dss.spi.DSSUtils
import kotlinx.datetime.toKotlinInstant
import java.io.ByteArrayOutputStream


open class KeySignatureService(val keyProvider: IKeyProviderService) : IKeySignatureService {

    override fun digest(signInput: SignInput): SignInput {
//        if (signInput.signMode == SignMode.DIGEST) throw SigningException("Signing mode must be DOCUMENT when creating a digest!")
        if (signInput.digestAlgorithm == null) throw SigningException("Cannot create a digest when the digest mode is not specified")
        if (signInput.digestAlgorithm == DigestAlg.NONE) throw SigningException("Cannot create a digest when the digest mode is set to NONE")
        val digest = DSSUtils.digest(signInput.digestAlgorithm.toDSS(), signInput.input)
        return SignInput(digest, SignMode.DIGEST, signInput.signingDate, signInput.digestAlgorithm, signInput.name)
    }

    override fun createSignature(signInput: SignInput, keyEntry: IKeyEntry): Signature {
        return keyProvider.createSignature(signInput, keyEntry)
    }

    override fun createSignature(signInput: SignInput, keyEntry: IKeyEntry, mgf: MaskGenFunction): Signature {
        return keyProvider.createSignature(signInput, keyEntry, mgf)
    }

    override fun createSignature(signInput: SignInput, keyEntry: IKeyEntry, signatureAlgorithm: SignatureAlg): Signature {
        return keyProvider.createSignature(signInput, keyEntry, signatureAlgorithm)
    }

    override fun isValidSignature(signInput: SignInput, signature: Signature, keyEntry: IKeyEntry): Boolean {
        return keyProvider.isValidSignature(signInput, signature, keyEntry)
    }


    override fun isValidSignature(signInput: SignInput, signature: Signature, publicKey: Key): Boolean {
        return keyProvider.isValidSignature(signInput, signature, publicKey)
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
            signatureConfiguration.signatureParameters.toDSS(
                timestampParameters = signatureConfiguration.timestampParameters,
                key = keyEntry
            )

        val toBeSigned = when (signatureConfiguration.signatureParameters.signatureForm()) {
            SignatureForm.CAdES -> adESService.toCAdESService().getDataToSign(toSign, signatureParameters as CAdESSignatureParameters)
            SignatureForm.PAdES -> adESService.toPAdESService(signatureConfiguration.timestampParameters).getDataToSign(toSign, signatureParameters as PAdESSignatureParameters)
            SignatureForm.PKCS7 -> adESService.toPKCS7Service().getDataToSign(toSign, signatureParameters as PKCS7SignatureParameters)
            SignatureForm.DIGEST -> ToBeSigned(origData.value)
            else -> throw SigningException("Determining sign input using signature form ${signatureConfiguration.signatureParameters.signatureForm()} not support")
        }
        return SignInput(
            input = toBeSigned.bytes,
            name = origData.name,
            signMode = signMode,
            digestAlgorithm = signatureConfiguration.signatureParameters.digestAlgorithm,
            signingDate = signatureParameters.bLevel().signingDate.toInstant().toKotlinInstant()
        )
    }

    override fun sign(origData: OrigData, keyEntry: IKeyEntry, signMode: SignMode, signatureConfiguration: SignatureConfiguration): SignOutput {
        val signInput = determineSignInput(origData, keyEntry, signMode, signatureConfiguration)
        return sign(origData, this.createSignature(signInput, keyEntry), signatureConfiguration)
    }

    override fun sign(origData: OrigData, signature: Signature, signatureConfiguration: SignatureConfiguration): SignOutput {
        val adESService = AdESServiceFactory.getService(signatureConfiguration)
        val signatureParameters =
            signatureConfiguration.signatureParameters.toDSS(
                key = signature.keyEntry,
                signatureAlg = signature.algorithm,
                timestampParameters = signatureConfiguration.timestampParameters,
                signingDate = signature.date
            )

        val toSign = InMemoryDocument(origData.value, origData.name)
        val signatureAlgorithm = signatureConfiguration.signatureParameters.getSignatureAlgorithm()
        val dssDocument = when (signatureConfiguration.signatureParameters.signatureForm()) {
            SignatureForm.CAdES -> adESService.toCAdESService()
                .signDocument(toSign, signatureParameters as CAdESSignatureParameters, signature.toDSS(signatureAlgorithm))
            SignatureForm.PAdES -> adESService.toPAdESService(signatureConfiguration.timestampParameters)
                .signDocument(toSign, signatureParameters as PAdESSignatureParameters, signature.toDSS(signatureAlgorithm))
            SignatureForm.PKCS7 -> adESService.toPKCS7Service()
                .signDocument(toSign, signatureParameters as PKCS7SignatureParameters, signature.toDSS(signatureAlgorithm))
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


}
