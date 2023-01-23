/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package com.sphereon.vdx.pkcs7

import eu.europa.esig.dss.cades.CAdESSignatureParameters
import eu.europa.esig.dss.cades.CMSUtils
import eu.europa.esig.dss.cades.signature.CMSSignedDataBuilder
import eu.europa.esig.dss.cades.validation.CAdESSignature
import eu.europa.esig.dss.enumerations.SignatureLevel
import eu.europa.esig.dss.exception.IllegalInputException
import eu.europa.esig.dss.model.DSSDocument
import eu.europa.esig.dss.pades.validation.PAdESSignature
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator
import eu.europa.esig.dss.pdf.IPdfObjFactory
import eu.europa.esig.dss.pdf.PDFSignatureService
import eu.europa.esig.dss.spi.x509.tsp.TSPSource
import eu.europa.esig.dss.validation.AdvancedSignature
import eu.europa.esig.dss.validation.CertificateVerifier
import eu.europa.esig.dss.validation.ValidationData
import org.bouncycastle.cms.CMSSignedData

/**
 * PAdES Baseline LT signature
 */
internal open class PKCS7BaselineLT
/**
 * The default constructor
 *
 * @param tspSource [TSPSource] to use
 * @param certificateVerifier [CertificateVerifier]
 * @param pdfObjectFactory [IPdfObjFactory]
 */
    (
    tspSource: TSPSource?, certificateVerifier: CertificateVerifier?,
    pdfObjectFactory: IPdfObjFactory?
) : PKCS7BaselineT(tspSource!!, certificateVerifier!!, pdfObjectFactory!!) {

    private val pAdESSignatureService: PDFSignatureService get() = pdfObjectFactory.newPAdESSignatureService()

    override fun extendSignatures(
        document: DSSDocument, documentValidator: PDFDocumentValidator,
        parameters: PKCS7SignatureParameters
    ): DSSDocument {
        var documentValidator = documentValidator
        val extendedDocument = super.extendSignatures(document, documentValidator, parameters)
        if (extendedDocument !== document) { // check if T-level has been added
            documentValidator = getPDFDocumentValidator(extendedDocument, parameters)
        }
        val signatures = documentValidator.signatures
        assertExtendSignaturePossible(signatures, parameters)
        val detachedTimestamps = documentValidator.detachedTimestamps
        val validationData = documentValidator.getValidationData(signatures, detachedTimestamps)
        val signatureService = pAdESSignatureService
        return signatureService.addDssDictionary(extendedDocument, validationData, parameters.passwordProtection)
    }

    override fun extendSignatures(document: DSSDocument, params: PKCS7SignatureParameters): DSSDocument {
        return super.extendSignatures(document, params)
    }

    private fun assertExtendSignaturePossible(signatures: List<AdvancedSignature>, parameters: PKCS7SignatureParameters) {
        for (signature in signatures) {
            val padesSignature = signature as PAdESSignature
            val signatureLevel = parameters.signatureLevel
            if (SignatureLevel.PAdES_BASELINE_LT == signatureLevel && padesSignature.hasLTAProfile()) {
                throw IllegalInputException(
                    String.format(
                        "Cannot extend signature to '%s'. The signature is already extended with LTA level.", signatureLevel
                    )
                )
            } else if (padesSignature.areAllSelfSignedCertificates()) {
                throw IllegalInputException("Cannot extend the signature. The signature contains only self-signed certificate chains!")
            }
        }
    }

    private fun assertExtendSignatureLevelLTPossible(cadesSignature: CAdESSignature, parameters: CAdESSignatureParameters) {
        val signatureLevel = parameters.signatureLevel
        if (SignatureLevel.PKCS7_LT == signatureLevel && cadesSignature.hasLTAProfile()) {
            throw IllegalInputException(
                String.format(
                    "Cannot extend signature to '%s'. The signedData is already extended with LTA level.", signatureLevel
                )
            )
        } else if (cadesSignature.areAllSelfSignedCertificates()) {
            throw IllegalInputException("Cannot extend the signature. The signature contains only self-signed certificate chains!")
        }
    }

    private fun extendWithValidationData(
        cmsSignedData: CMSSignedData,
        validationDataForInclusion: ValidationData
    ): CMSSignedData? {
        val cmsSignedDataBuilder = CMSSignedDataBuilder(certificateVerifier)
        return cmsSignedDataBuilder.extendCMSSignedData(cmsSignedData, validationDataForInclusion)
    }

    protected open fun includesATSv2(cmsSignedData: CMSSignedData): Boolean {
        for (signerInformation in cmsSignedData.signerInfos) {
            if (CMSUtils.containsATSTv2(signerInformation)) {
                return true
            }
        }
        return false
    }
}
