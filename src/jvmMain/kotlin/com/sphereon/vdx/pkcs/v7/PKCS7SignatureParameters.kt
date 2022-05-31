package com.sphereon.vdx.pkcs.v7

import eu.europa.esig.dss.cades.CAdESSignatureParameters
import eu.europa.esig.dss.enumerations.CertificationPermission
import eu.europa.esig.dss.enumerations.SignatureForm
import eu.europa.esig.dss.enumerations.SignatureLevel
import eu.europa.esig.dss.pades.PAdESCommonParameters
import eu.europa.esig.dss.pades.SignatureImageParameters
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import java.util.Date
import java.util.TimeZone

class PKCS7SignatureParameters : CAdESSignatureParameters(), PAdESCommonParameters {

    private val reason: String? = null
    private val contactInfo: String? = null
    private val location: String? = null
    private val signatureSize = 9472
    private val signatureFilter = PDSignature.FILTER_ADOBE_PPKLITE
    private val signatureSubFilter = PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED
    private val signerName: String? = null
    private var signatureImageParameters: SignatureImageParameters? = null
    private val permission: CertificationPermission? = null
    private val passwordProtection: String? = null
    private val signingTimeZone = TimeZone.getDefault()

    override fun setSignatureLevel(signatureLevel: SignatureLevel?) {
        if (signatureLevel != null && SignatureForm.PKCS7 == signatureLevel.signatureForm) {
            super.setSignatureLevel(signatureLevel)
        } else {
            throw IllegalArgumentException("Only PKCS7 form is allowed!")
        }
    }

    override fun getSigningDate(): Date {
        return bLevel().signingDate
    }

    override fun getFilter(): String {
        return this.signatureFilter.name
    }

    override fun getSubFilter(): String {
        return this.signatureSubFilter.name
    }

    override fun getImageParameters(): SignatureImageParameters {
        if (signatureImageParameters == null) {
            signatureImageParameters = SignatureImageParameters()
        }
        return signatureImageParameters!!
    }

    override fun getContentSize(): Int {
        return signatureSize
    }

    override fun getPasswordProtection(): String? {
        return this.passwordProtection
    }
}