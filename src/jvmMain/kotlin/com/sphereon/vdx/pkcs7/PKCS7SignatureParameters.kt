package com.sphereon.vdx.pkcs7

import com.sphereon.vdx.ades.model.PdfSignatureMode
import eu.europa.esig.dss.cades.CAdESSignatureParameters
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters
import eu.europa.esig.dss.enumerations.CertificationPermission
import eu.europa.esig.dss.pades.PAdESCommonParameters
import eu.europa.esig.dss.pades.PAdESProfileParameters
import eu.europa.esig.dss.pades.PAdESTimestampParameters
import eu.europa.esig.dss.pades.SignatureImageParameters
import eu.europa.esig.dss.pdf.PdfSignatureCache
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import java.util.Date
import java.util.TimeZone

class PKCS7SignatureParameters : CAdESSignatureParameters(), PAdESCommonParameters {

    var reason: String? = null
    var contactInfo: String? = null
    var location: String? = null
    var signerName: String? = null
    var permission: CertificationPermission? = null
    var signatureMode: PdfSignatureMode? = PdfSignatureMode.APPROVAL
    var signingTimeZone: TimeZone? = TimeZone.getDefault()

    var signatureImageParameters: SignatureImageParameters? = null
    private var passwordProtection: String? = null
    private val signatureSize =  32768
    private val signatureFilter = PDSignature.FILTER_ADOBE_PPKLITE
    private val signatureSubFilter = PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED

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

    fun setAppName(appName: String) {
        this.appName = appName
    }

    override fun getAppName(): String {
        return appName
    }

    override fun getPdfSignatureCache(): PdfSignatureCache {
        return getContext().pdfToBeSignedCache
    }

    override fun getContext(): PAdESProfileParameters {
        if (context == null) {
            context = PAdESProfileParameters()
        }
        return context as PAdESProfileParameters
    }

    /**
     * Sets a password string
     *
     * @param passwordProtection [String] password to set
     */
    fun setPasswordProtection(passwordProtection: String?) {
        this.passwordProtection = passwordProtection
    }


    override fun getContentTimestampParameters(): PAdESTimestampParameters {
        if (contentTimestampParameters == null) {
            contentTimestampParameters = PAdESTimestampParameters()
        }
        return contentTimestampParameters as PAdESTimestampParameters
    }

    override fun setContentTimestampParameters(contentTimestampParameters: CAdESTimestampParameters) {
        if (contentTimestampParameters is PAdESTimestampParameters) {
            this.contentTimestampParameters = contentTimestampParameters
        } else {
            this.contentTimestampParameters = PAdESTimestampParameters(contentTimestampParameters.digestAlgorithm)
        }
    }

    override fun getSignatureTimestampParameters(): PAdESTimestampParameters {
        if (signatureTimestampParameters == null) {
            throw RuntimeException("signatureTimestampParameters may not be null")
        }
        return signatureTimestampParameters as PAdESTimestampParameters
    }

    override fun setSignatureTimestampParameters(signatureTimestampParameters: CAdESTimestampParameters) {
        if (signatureTimestampParameters is PAdESTimestampParameters) {
            this.signatureTimestampParameters = signatureTimestampParameters
        } else {
            this.signatureTimestampParameters = PAdESTimestampParameters(signatureTimestampParameters.digestAlgorithm)
        }
    }

    override fun getArchiveTimestampParameters(): PAdESTimestampParameters {
        if (archiveTimestampParameters == null) {
            archiveTimestampParameters = PAdESTimestampParameters()
        }
        return archiveTimestampParameters as PAdESTimestampParameters
    }

    override fun setArchiveTimestampParameters(archiveTimestampParameters: CAdESTimestampParameters) {
        if (archiveTimestampParameters is PAdESTimestampParameters) {
            this.archiveTimestampParameters = archiveTimestampParameters
        } else {
            this.archiveTimestampParameters = PAdESTimestampParameters(archiveTimestampParameters.digestAlgorithm)
        }
    }
}
