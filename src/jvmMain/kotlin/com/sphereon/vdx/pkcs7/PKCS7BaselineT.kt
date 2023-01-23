/**
 * DSS - Digital Signature Services Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 *
 * This library is free software; you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your option) any later version.
 *
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 *
 * You should have received a copy of the GNU Lesser General Public License along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package com.sphereon.vdx.pkcs7

import eu.europa.esig.dss.cades.CAdESSignatureParameters
import eu.europa.esig.dss.cades.CMSUtils
import eu.europa.esig.dss.cades.validation.CAdESSignature
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator
import eu.europa.esig.dss.enumerations.DigestAlgorithm
import eu.europa.esig.dss.enumerations.SignatureLevel
import eu.europa.esig.dss.exception.IllegalInputException
import eu.europa.esig.dss.model.DSSDocument
import eu.europa.esig.dss.model.DSSException
import eu.europa.esig.dss.pades.PAdESTimestampParameters
import eu.europa.esig.dss.pades.PAdESUtils
import eu.europa.esig.dss.pades.timestamp.PAdESTimestampService
import eu.europa.esig.dss.pades.validation.PAdESSignature
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator
import eu.europa.esig.dss.pdf.IPdfObjFactory
import eu.europa.esig.dss.pdf.PDFSignatureService
import eu.europa.esig.dss.signature.SignatureExtension
import eu.europa.esig.dss.signature.SignatureRequirementsChecker
import eu.europa.esig.dss.spi.DSSASN1Utils
import eu.europa.esig.dss.spi.DSSUtils
import eu.europa.esig.dss.spi.x509.tsp.TSPSource
import eu.europa.esig.dss.utils.Utils
import eu.europa.esig.dss.validation.CertificateVerifier
import org.bouncycastle.asn1.ASN1Object
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.SignerInformationStore
import java.io.IOException
import java.util.Objects

/**
 * PAdES Baseline T signature
 *
 */
internal open class PKCS7BaselineT constructor(
    tspSource: TSPSource,
    certificateVerifier: CertificateVerifier,
    pdfObjectFactory: IPdfObjFactory
) : SignatureExtension<PKCS7SignatureParameters> {
    /** The TSPSource to obtain a timestamp  */
    private val tspSource: TSPSource

    /** The used CertificateVerifier  */
    protected val certificateVerifier: CertificateVerifier

    /** The used implementation for processing of a PDF document  */
    @JvmField
    protected val pdfObjectFactory: IPdfObjFactory

    /**
     * The default constructor
     *
     * @param tspSource [TSPSource]
     * @param certificateVerifier [CertificateVerifier]
     * @param pdfObjectFactory [IPdfObjFactory]
     */
    init {
        Objects.requireNonNull(tspSource, "TSPSource shall be defined!")
        Objects.requireNonNull(certificateVerifier, "CertificateVerifier shall be defined!")
        Objects.requireNonNull(pdfObjectFactory, "pdfObjectFactory shall be defined!")
        this.tspSource = tspSource
        this.certificateVerifier = certificateVerifier
        this.pdfObjectFactory = pdfObjectFactory
    }

    override fun extendSignatures(document: DSSDocument, params: PKCS7SignatureParameters): DSSDocument {
        assertExtensionPossible(document)
        // Will add a DocumentTimeStamp. signature-timestamp (CMS) is impossible to add while extending
        val pdfDocumentValidator = getPDFDocumentValidator(document, params)
        return extendSignatures(document, pdfDocumentValidator, params)
    }

    /**
     * This method performs a document extension
     *
     * @param document [DSSDocument]
     * @param documentValidator [PDFDocumentValidator]
     * @param parameters [PKCS7SignatureParameters]
     * @return [DSSDocument] extended document
     */
    protected open fun extendSignatures(
        document: DSSDocument, documentValidator: PDFDocumentValidator,
        parameters: PKCS7SignatureParameters
    ): DSSDocument {
        val signatures = documentValidator.signatures
        if (Utils.isCollectionEmpty(signatures)) {
            throw IllegalInputException("No signatures found to be extended!")
        }
        var tLevelExtensionRequired = false
        val signatureRequirementsChecker = SignatureRequirementsChecker(
            certificateVerifier, parameters
        )
        for (signature in signatures) {
            val padesSignature = signature as PAdESSignature
            if (requiresDocumentTimestamp(padesSignature, parameters)) {
                assertExtendSignatureToTPossible(padesSignature, parameters)
                signatureRequirementsChecker.assertSigningCertificateIsValid(padesSignature)
                tLevelExtensionRequired = true
            }
        }
        return if (tLevelExtensionRequired) {
            // Will add a DocumentTimeStamp. signature-timestamp (CMS) is impossible to add while extending
            timestampDocument(
                document, parameters.signatureTimestampParameters,
                parameters.passwordProtection, signatureTimestampService
            )
        } else {
            document
        }
    }

    private val signatureTimestampService: PDFSignatureService
        /**
         * This method returns a `PDFSignatureService` to be used for a signature timestamp creation
         *
         * @return [PDFSignatureService]
         */
        private get() = pdfObjectFactory.newSignatureTimestampService()

    /**
     * Timestamp document
     *
     * @param document [DSSDocument] to timestamp
     * @param timestampParameters [PAdESTimestampParameters]
     * @param pwd [String] password if required
     * @param pdfSignatureService [PDFSignatureService] to be used
     * @return [DSSDocument] timestamped
     */
    protected fun timestampDocument(
        document: DSSDocument?,
        timestampParameters: PAdESTimestampParameters, pwd: String?,
        pdfSignatureService: PDFSignatureService?
    ): DSSDocument {
        val padesTimestampService = PAdESTimestampService(tspSource, pdfSignatureService)
        timestampParameters.passwordProtection = pwd
        return padesTimestampService.timestampDocument(document, timestampParameters)
    }

    /**
     * Returns a document validator instance
     *
     * @param document [DSSDocument] document to be validated
     * @param parameters [PKCS7SignatureParameters] used to create/extend the signature(s)
     * @return [PDFDocumentValidator]
     */
    protected fun getPDFDocumentValidator(document: DSSDocument?, parameters: PKCS7SignatureParameters): PDFDocumentValidator {
        val pdfDocumentValidator = PDFDocumentValidator(document)
        pdfDocumentValidator.setCertificateVerifier(certificateVerifier)
        pdfDocumentValidator.setPasswordProtection(parameters.passwordProtection)
        pdfDocumentValidator.setPdfObjFactory(pdfObjectFactory)
        return pdfDocumentValidator
    }

    /**
     * Checks if the document can be extended
     *
     * @param document [DSSDocument]
     */
    protected fun assertExtensionPossible(document: DSSDocument) {
        if (!PAdESUtils.isPDFDocument(document)) {
            throw IllegalInputException(
                String.format(
                    "Unable to extend the document with name '%s'. " +
                            "PDF document is expected!", document.name
                )
            )
        }
    }

    private fun requiresDocumentTimestamp(signature: PAdESSignature?, signatureParameters: PKCS7SignatureParameters): Boolean {
        return SignatureLevel.PAdES_BASELINE_T == signatureParameters.signatureLevel || !signature!!.hasTProfile()
    }

    private fun assertExtendSignatureToTPossible(signature: PAdESSignature?, parameters: PKCS7SignatureParameters) {
        val signatureLevel = parameters.signatureLevel
        if (SignatureLevel.PAdES_BASELINE_T == signatureLevel && (signature!!.hasLTAProfile() || signature.hasLTProfile() && !signature.areAllSelfSignedCertificates())) {
            throw IllegalInputException(
                String.format(
                    "Cannot extend signature to '%s'. The signature is already extended with LT level.", signatureLevel
                )
            )
        }
    }

    fun extendCMSSignatures(cmsSignedData: CMSSignedData?, parameters: PKCS7SignatureParameters): CMSSignedData {
        // extract signerInformations before pre-extension
        val signerInformationCollection = cmsSignedData!!.signerInfos.signers
        if (Utils.isCollectionEmpty(signerInformationCollection)) {
            throw IllegalInputException("Unable to extend the document! No signatures found.")
        }

        val signerInformationsToExtend = cmsSignedData.signerInfos.signers
        val signatureIdsToExtend: MutableList<String> = ArrayList()
        val validator: CMSDocumentValidator = getDocumentValidator(cmsSignedData, parameters)
        val signatures = validator.signatures
        for (signature in signatures) {
            val cadesSignature = signature as CAdESSignature
            if (signerInformationsToExtend.contains(cadesSignature.signerInformation)) {
                signatureIdsToExtend.add(cadesSignature.id)
            }
        }

        return extendCMSSignatures(cmsSignedData, parameters, signatureIdsToExtend)
    }

    protected fun extendCMSSignatures(
        cmsSignedData: CMSSignedData,
        parameters: PKCS7SignatureParameters,
        signatureIdsToExtend: MutableList<String>
    ): CMSSignedData {
        val newSignerInformationList: MutableList<SignerInformation> = java.util.ArrayList()

        val documentValidator = getDocumentValidator(cmsSignedData, parameters)
        val signatures = documentValidator.signatures
        if (Utils.isCollectionEmpty(signatures)) {
            throw IllegalInputException("There is no signature to extend!")
        }

        val signatureRequirementsChecker = SignatureRequirementsChecker(
            certificateVerifier, parameters
        )

        for (signature in signatures) {
            val cadesSignature = signature as CAdESSignature
            val signerInformation = cadesSignature.signerInformation
            var newSignerInformation = signerInformation
            if (signatureIdsToExtend.contains(cadesSignature.id)) {
                newSignerInformation = extendSignerInformation(
                    cmsSignedData, signerInformation, parameters,
                    signatureRequirementsChecker
                )
            }
            newSignerInformationList.add(newSignerInformation)
        }

        return replaceSigners(cmsSignedData, newSignerInformationList)
    }


    protected open fun extendSignerInformation(
        signedData: CMSSignedData, signerInformation: SignerInformation,
        parameters: PKCS7SignatureParameters,
        signatureRequirementsChecker: SignatureRequirementsChecker
    ): SignerInformation {
        val cadesSignature: CAdESSignature = newCAdESSignature(signedData, signerInformation, parameters.detachedContents)
        if (tLevelExtensionRequired(cadesSignature, parameters)) {
            assertExtendSignatureLevelTPossible(cadesSignature, parameters)
            signatureRequirementsChecker.assertSigningCertificateIsValid(cadesSignature)
            var unsignedAttributes = CMSUtils.getUnsignedAttributes(signerInformation)
            unsignedAttributes = addSignatureTimestampAttribute(signerInformation, unsignedAttributes, parameters)
            return SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes)
        }
        return signerInformation
    }

    protected fun assertExtendSignatureLevelTPossible(cadesSignature: CAdESSignature, parameters: CAdESSignatureParameters) {
        val exceptionMessage = "Cannot extend signature to '%s'. The signedData is already extended with %s."
        if (SignatureLevel.CAdES_BASELINE_T == parameters.signatureLevel && (cadesSignature.hasLTAProfile() || cadesSignature.hasLTProfile() && !cadesSignature.areAllSelfSignedCertificates())) {
            throw IllegalInputException(String.format(exceptionMessage, parameters.signatureLevel, "LT level"))
        }
        val unsignedAttributes = CMSUtils.getUnsignedAttributes(cadesSignature.signerInformation)
        if (unsignedAttributes[PKCSObjectIdentifiers.id_aa_ets_escTimeStamp] != null) {
            throw IllegalInputException(
                String.format(
                    exceptionMessage,
                    parameters.signatureLevel, PKCSObjectIdentifiers.id_aa_ets_escTimeStamp.id
                )
            )
        }
    }

    protected fun tLevelExtensionRequired(cadesSignature: CAdESSignature, parameters: CAdESSignatureParameters): Boolean {
        return SignatureLevel.CAdES_BASELINE_T == parameters.signatureLevel || !cadesSignature.hasTProfile()
    }

    protected open fun getDocumentValidator(signedData: CMSSignedData, parameters: CAdESSignatureParameters): CMSDocumentValidator {
        val documentValidator = CMSDocumentValidator(signedData)
        documentValidator.setCertificateVerifier(certificateVerifier)
        documentValidator.setDetachedContents(parameters.detachedContents)
        return documentValidator
    }

    protected open fun replaceSigners(cmsSignedData: CMSSignedData, newSignerInformationList: List<SignerInformation?>): CMSSignedData {
        val newSignerStore = SignerInformationStore(newSignerInformationList)
        val updatedCmsSignedData = CMSSignedData.replaceSigners(cmsSignedData, newSignerStore)
        return CMSUtils.populateDigestAlgorithmSet(updatedCmsSignedData, cmsSignedData)
    }

    protected open fun newCAdESSignature(
        cmsSignedData: CMSSignedData?, signerInformation: SignerInformation,
        detachedContents: List<DSSDocument?>
    ): CAdESSignature {
        val cadesSignature = CAdESSignature(cmsSignedData, signerInformation)
        cadesSignature.detachedContents = detachedContents
        cadesSignature.prepareOfflineCertificateVerifier(certificateVerifier)
        return cadesSignature
    }

    protected  fun addSignatureTimestampAttribute(
        signerInformation: SignerInformation, unsignedAttributes: AttributeTable,
        parameters: CAdESSignatureParameters
    ): AttributeTable? {
        val timestampDigestAlgorithm = parameters.signatureTimestampParameters.digestAlgorithm
        val signatureTimeStamp: ASN1Object = getTimeStampAttributeValue(signerInformation.signature, timestampDigestAlgorithm)
        return unsignedAttributes.add(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, signatureTimeStamp)
    }

    protected open fun getTimeStampAttributeValue(
        messageToTimestamp: ByteArray, timestampDigestAlgorithm: DigestAlgorithm,
        vararg attributesForTimestampToken: Attribute
    ): ASN1Object {
        return try {
            val timestampDigest = DSSUtils.digest(timestampDigestAlgorithm, messageToTimestamp)
            val timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, timestampDigest)
            var cmsSignedDataTimeStampToken = CMSSignedData(timeStampToken.bytes)

            // TODO (27/08/2014): attributesForTimestampToken cannot be null: to be modified
            if (attributesForTimestampToken != null) {
                // timeStampToken contains one and only one signer
                val signerInformation = cmsSignedDataTimeStampToken.signerInfos.signers.iterator().next()
                var unsignedAttributes = CMSUtils.getUnsignedAttributes(signerInformation)
                for (attributeToAdd in attributesForTimestampToken) {
                    val attrType = attributeToAdd.attrType
                    val objectAt = attributeToAdd.attrValues.getObjectAt(0)
                    unsignedAttributes = unsignedAttributes!!.add(attrType, objectAt)
                }
                // Unsigned attributes cannot be empty (RFC 5652 5.3)
                if (unsignedAttributes!!.size() == 0) {
                    unsignedAttributes = null
                }
                val newSignerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes)
                val signerInformationList: MutableList<SignerInformation> = java.util.ArrayList()
                signerInformationList.add(newSignerInformation)
                val newSignerStore = SignerInformationStore(signerInformationList)
                cmsSignedDataTimeStampToken = CMSSignedData.replaceSigners(cmsSignedDataTimeStampToken, newSignerStore)
            }
            val newTimeStampTokenBytes = cmsSignedDataTimeStampToken.encoded
            DSSASN1Utils.toASN1Primitive(newTimeStampTokenBytes)
        } catch (e: IOException) {
            throw DSSException("Cannot obtain timestamp attribute value.", e)
        } catch (e: CMSException) {
            throw DSSException("Cannot obtain timestamp attribute value.", e)
        }
    }
}
