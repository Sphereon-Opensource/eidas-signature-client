package com.sphereon.vdx.ades.sign

import com.sphereon.vdx.ades.SigningException
import com.sphereon.vdx.ades.enums.*
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.pki.IKeyProviderService
import com.sphereon.vdx.ades.sign.util.*
import com.sphereon.vdx.pkcs7.PKCS7SignatureParameters
import eu.europa.esig.dss.cades.CAdESSignatureParameters
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.model.ToBeSigned
import eu.europa.esig.dss.pades.PAdESSignatureParameters
import eu.europa.esig.dss.spi.DSSUtils
import kotlinx.datetime.toKotlinInstant
import mu.KotlinLogging
import java.io.ByteArrayOutputStream

private val logger = KotlinLogging.logger {}

open class KeySignatureService(val keyProvider: IKeyProviderService) : IKeySignatureService {

    override fun digest(signInput: SignInput): SignInput {
        logger.entry(signInput)
        logger.info { "Creating a digest for signInput named '${signInput.name}' with date ${signInput.signingDate}, signature mode '${signInput.signMode.name}' and digest mode '${signInput.digestAlgorithm?.name ?: "<unknown>"}'" }
//        if (signInput.signMode == SignMode.DIGEST) throw SigningException("Signing mode must be DOCUMENT when creating a digest!")
        if (signInput.digestAlgorithm == null) throw SigningException("Cannot create a digest when the digest mode is not specified")
        if (signInput.digestAlgorithm == DigestAlg.NONE) throw SigningException("Cannot create a digest when the digest mode is set to NONE")
        val digest = DSSUtils.digest(signInput.digestAlgorithm.toDSS(), signInput.input)

        logger.info { "Created a digest for signInput named '${signInput.name}' with date ${signInput.signingDate}, signature mode '${signInput.signMode.name}' and digest mode '${signInput.digestAlgorithm.name}'" }
        return logger.exit(SignInput(digest, SignMode.DIGEST, signInput.signingDate, signInput.digestAlgorithm, signInput.name, signInput.binding))
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
        logger.entry(origData, keyEntry, signMode, signatureConfiguration)
        val adESService = AdESServiceFactory.getService(signatureConfiguration)
        val toSign = InMemoryDocument(origData.value, origData.name)
        val signatureParameters =
            signatureConfiguration.signatureParameters.toDSS(
                timestampParameters = signatureConfiguration.timestampParameters,
                key = keyEntry
            )

        val signatureForm = signatureConfiguration.signatureParameters.signatureForm()
        logger.info { "Determining sign input for data with name '${origData.name}', key id '${keyEntry.kid}' in mode ${signatureForm.name}..." }
        val toBeSigned = when (signatureForm) {
            SignatureForm.CAdES -> adESService.toCAdESService().getDataToSign(toSign, signatureParameters as CAdESSignatureParameters)
            SignatureForm.PAdES -> adESService.toPAdESService(signatureConfiguration.timestampParameters)
                .getDataToSign(toSign, signatureParameters as PAdESSignatureParameters)
            SignatureForm.PKCS7 -> adESService.toPKCS7Service().getDataToSign(toSign, signatureParameters as PKCS7SignatureParameters)
            SignatureForm.DIGEST -> ToBeSigned(origData.value)
            else -> throw SigningException("Determining sign input using signature form ${signatureConfiguration.signatureParameters.signatureForm()} not support")
        }
        val signInput = SignInput(
            input = toBeSigned.bytes,
            name = origData.name,
            signMode = signMode,
            digestAlgorithm = signatureConfiguration.signatureParameters.digestAlgorithm,
            signingDate = signatureParameters.bLevel().signingDate.toInstant().toKotlinInstant(),
            binding = ConfigKeyBinding(
                kid = keyEntry.kid,
                keyProviderId = keyProvider.settings.id
            )
        )

        logger.info { "Determined sign input for data with name '${origData.name}', key id '${keyEntry.kid}' in mode ${signatureForm.name}. Signing date: ${signInput.signingDate}" }
        logger.exit(signInput)
        return signInput
    }

    override fun sign(origData: OrigData, keyEntry: IKeyEntry, signMode: SignMode, signatureConfiguration: SignatureConfiguration): SignOutput {
        val signInput = determineSignInput(origData, keyEntry, signMode, signatureConfiguration)
        return sign(origData, this.createSignature(signInput, keyEntry), signatureConfiguration)
    }

    override fun sign(origData: OrigData, signature: Signature, signatureConfiguration: SignatureConfiguration): SignOutput {
        logger.entry(origData, signature, signatureConfiguration)
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
        val signatureForm = signatureConfiguration.signatureParameters.signatureForm()
        logger.info { "Merging signature with original document named '${origData.name}' at date ${signature.date}, using key Id ${signature.keyEntry.kid}, and provider ${signature.providerId}, in mode '$signatureForm'..." }
        val dssDocument = when (signatureForm) {
            SignatureForm.CAdES -> adESService.toCAdESService()
                .signDocument(toSign, signatureParameters as CAdESSignatureParameters, signature.toDSS(signatureAlgorithm))
            SignatureForm.PAdES -> adESService.toPAdESService(signatureConfiguration.timestampParameters)
                .signDocument(toSign, signatureParameters as PAdESSignatureParameters, signature.toDSS(signatureAlgorithm))
            SignatureForm.PKCS7 -> adESService.toPKCS7Service()
                .signDocument(toSign, signatureParameters as PKCS7SignatureParameters, signature.toDSS(signatureAlgorithm))
            else -> throw SigningException("Signing using signature form ${signatureConfiguration.signatureParameters.signatureForm()} not support")
        }

        ByteArrayOutputStream().use { baos ->
            dssDocument.writeTo(baos)
            val signOutput = SignOutput(
                value = baos.toByteArray(),
                signature = signature,
                mimeType = dssDocument.mimeType?.mimeTypeString,
                signMode = signature.signMode,
                digestAlgorithm = signature.algorithm.digestAlgorithm ?: signatureConfiguration.signatureParameters.digestAlgorithm,
                name = dssDocument.name
            )

            logger.info { "Merged signature with original document named '${origData.name}' at date ${signature.date}, using key Id ${signature.keyEntry.kid}, and provider ${signature.providerId}, in mode '$signatureForm'" }
            logger.exit(signOutput)
            return signOutput
        }

    }


    override fun simpleSign(origData: OrigData,
                            keyEntry: IKeyEntry,
                            signMode: SignMode,
                            signatureConfiguration: SignatureConfiguration): SignOutput {
        val signInput: SignInput = determineSignInput(origData, keyEntry, signMode, signatureConfiguration)
        val digestInput = digest(signInput)
        val signature = createSignature(digestInput, keyEntry)
        return sign(origData, signature, signatureConfiguration)
    }
}
