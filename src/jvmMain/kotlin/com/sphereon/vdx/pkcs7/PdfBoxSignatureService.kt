package com.sphereon.vdx.pkcs7

import eu.europa.esig.dss.pades.PAdESCommonParameters
import eu.europa.esig.dss.pades.PAdESSignatureParameters
import eu.europa.esig.dss.pdf.PDFServiceMode
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxSignatureService
import eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer.PdfBoxNativeSignatureDrawerFactory
import eu.europa.esig.dss.utils.Utils
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.slf4j.LoggerFactory
import java.io.IOException
import java.util.Calendar

class PdfBoxSignatureService : PdfBoxSignatureService(PDFServiceMode.SIGNATURE, PdfBoxNativeSignatureDrawerFactory()) {
    private val LOG = LoggerFactory.getLogger(PdfBoxSignatureService::class.java)

    override fun createSignatureDictionary(pdDocument: PDDocument, parameters: PAdESCommonParameters): PDSignature {
        val signature = PDSignature()

        val currentType = COSName.getPDFName(type)
        signature.setType(currentType)

        if (Utils.isStringNotEmpty(parameters.filter)) {
            signature.setFilter(COSName.getPDFName(parameters!!.filter))
        }
        // sub-filter for basic and PAdES Part 2 signatures
        // sub-filter for basic and PAdES Part 2 signatures
        if (Utils.isStringNotEmpty(parameters!!.subFilter)) {
            signature.setSubFilter(COSName.getPDFName(parameters!!.subFilter))
        }

        if (COSName.SIG == currentType) {
            when (parameters) {
                is PAdESSignatureParameters -> {
                    if (Utils.isStringNotEmpty(parameters.signerName)) {
                        signature.name = parameters.signerName
                        if (Utils.isStringNotEmpty(parameters.contactInfo)) {
                            signature.contactInfo = parameters.contactInfo
                        }
                        if (Utils.isStringNotEmpty(parameters.location)) {
                            signature.location = parameters.location
                        }
                        if (Utils.isStringNotEmpty(parameters.reason)) {
                            signature.reason = parameters.reason
                        }
                        val permission = parameters.permission
                        // A document can contain only one signature field that contains a DocMDP
                        // transform method;
                        // it shall be the first signed field in the document.
                        if (permission != null && !containsFilledSignature(pdDocument)) {
                            setMDPPermission(pdDocument, signature, permission.code)
                        }

                        // the signing date, needed for valid signature
                        val cal = Calendar.getInstance()
                        cal.time = parameters.signingDate
                        cal.timeZone = parameters.signingTimeZone
                        signature.signDate = cal
                    }
                }
                is PKCS7SignatureParameters -> {
                    if (Utils.isStringNotEmpty(parameters.signerName)) {
                        signature.name = parameters.signerName
                        if (Utils.isStringNotEmpty(parameters.contactInfo)) {
                            signature.contactInfo = parameters.contactInfo
                        }
                        if (Utils.isStringNotEmpty(parameters.location)) {
                            signature.location = parameters.location
                        }
                        if (Utils.isStringNotEmpty(parameters.reason)) {
                            signature.reason = parameters.reason
                        }
                        val permission = parameters.permission
                        // A document can contain only one signature field that contains a DocMDP
                        // transform method;
                        // it shall be the first signed field in the document.
                        if (permission != null && !containsFilledSignature(pdDocument)) {
                            setMDPPermission(pdDocument, signature, permission.code)
                        }

                        // the signing date, needed for valid signature
                        val cal = Calendar.getInstance()
                        cal.time = parameters.signingDate
                        cal.timeZone = parameters.signingTimeZone
                        signature.signDate = cal
                    }
                }
            }
        }
        return signature
    }

    private fun containsFilledSignature(pdDocument: PDDocument): Boolean {
        return try {
            val signatures = pdDocument.signatureDictionaries
            for (pdSignature in signatures) {
                if (pdSignature.cosObject.containsKey(COSName.BYTERANGE)) {
                    return true
                }
            }
            false
        } catch (e: IOException) {
            LOG.warn("Cannot read the existing signature(s)", e)
            false
        }
    }

}