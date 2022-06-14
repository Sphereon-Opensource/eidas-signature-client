package com.sphereon.vdx.pkcs7

import com.sphereon.vdx.ades.model.PdfSignatureMode
import eu.europa.esig.dss.cades.CAdESSignatureParameters
import eu.europa.esig.dss.enumerations.CertificationPermission
import eu.europa.esig.dss.enumerations.SignatureForm
import eu.europa.esig.dss.enumerations.SignatureLevel
import eu.europa.esig.dss.pades.PAdESCommonParameters
import eu.europa.esig.dss.pades.PAdESSignatureParameters
import eu.europa.esig.dss.pades.PAdESTimestampParameters
import eu.europa.esig.dss.pades.SignatureImageParameters
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import java.util.*

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
    private val signatureSize = 9472
    private val signatureFilter = PDSignature.FILTER_ADOBE_PPKLITE
    private val signatureSubFilter = PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED

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

    internal fun toPAdESSignatureParameters(): PAdESSignatureParameters {
        val parameters = PAdESSignatureParameters()
        parameters.contactInfo = this.contactInfo
        parameters.location = this.location
        parameters.permission = this.permission
        parameters.reason = this.reason
        parameters.signerName = this.signerName
        parameters.signingTimeZone = this.signingTimeZone
        parameters.passwordProtection = this.passwordProtection
        parameters.filter = this.signatureFilter.name
        parameters.subFilter = this.signatureSubFilter.name
        parameters.detachedContents = this.detachedContents
        parameters.contentTimestamps = this.contentTimestamps
        parameters.contentIdentifierPrefix = this.contentIdentifierPrefix
        parameters.contentIdentifierSuffix = this.contentIdentifierSuffix
        parameters.contentHintsType = this.contentHintsType
        parameters.contentHintsDescription = this.contentHintsDescription
        parameters.certificateChain = this.certificateChain
        parameters.digestAlgorithm = this.digestAlgorithm
        parameters.encryptionAlgorithm = this.encryptionAlgorithm
        parameters.isCheckCertificateRevocation = this.isCheckCertificateRevocation
        parameters.isEn319122 = this.isEn319122
        parameters.isGenerateTBSWithoutCertificate = this.isGenerateTBSWithoutCertificate
        parameters.isSignWithExpiredCertificate = this.isSignWithExpiredCertificate
        parameters.isSignWithNotYetValidCertificate = this.isSignWithNotYetValidCertificate
        parameters.maskGenerationFunction = this.maskGenerationFunction
        parameters.archiveTimestampParameters = PAdESTimestampParameters(this.archiveTimestampParameters.digestAlgorithm)
        parameters.archiveTimestampParameters.filter = this.signatureFilter.name
        parameters.archiveTimestampParameters.subFilter = this.signatureSubFilter.name
        parameters.contentTimestampParameters = PAdESTimestampParameters(this.contentTimestampParameters.digestAlgorithm)
        parameters.contentTimestampParameters.filter = this.signatureFilter.name
        parameters.contentTimestampParameters.subFilter = this.signatureSubFilter.name
        parameters.signatureTimestampParameters = PAdESTimestampParameters(this.signatureTimestampParameters.digestAlgorithm)
        parameters.signatureTimestampParameters.filter = this.signatureFilter.name
        parameters.signatureTimestampParameters.subFilter = this.signatureSubFilter.name
        parameters.signatureLevel = SignatureLevel.PAdES_BASELINE_B // TODO check if this has the same effect
        return parameters
    }
}
