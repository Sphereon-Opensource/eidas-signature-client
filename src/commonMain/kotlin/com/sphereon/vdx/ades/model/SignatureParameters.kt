package com.sphereon.vdx.ades.model

import com.sphereon.vdx.ades.Base64Serializer
import com.sphereon.vdx.ades.enums.*
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

@kotlinx.serialization.Serializable
data class SignatureParameters(
    /**
     * Signing certificate
     */
    val signingCertificate: Certificate? = null,

    /**
     * Signing certificate chain
     */
    val certificateChain: List<Certificate>? = emptyList(),

    /**
     * The documents to be signed
     *//*
    private val detachedContents: List<SignInput>,
*/
    /**
     * ASiC Container type
     */
    val asicContainerType: ASiCContainerType? = null,


    /**
     * This variable indicates if it is possible to sign with an expired certificate.
     *
     * Default : false
     */
    val signWithExpiredCertificate: Boolean? = false,

    /**
     * This variable indicates if it is possible to sign with a not yet valid certificate.
     *
     * Default : false
     */
    val signWithNotYetValidCertificate: Boolean? = false,

    /**
     * This variable indicates whether a signing certificate revocation shall be checked.
     *
     * Default : false
     */
    val checkCertificateRevocation: Boolean? = false,


    /**
     * This variable indicates the expected signature packaging
     */
    val signaturePackaging: SignaturePackaging? = null,


    /**
     * XAdES: The ds:SignatureMethod indicates the algorithms used to sign ds:SignedInfo.
     */
    private val signatureAlgorithm: SignatureAlg = SignatureAlg.RSA_SHA256,

    /**
     * XAdES: The digest algorithm used to hash ds:SignedInfo.
     */
    val digestAlgorithm: DigestAlg = signatureAlgorithm.digestAlgorithm!!,

    /**
     * XAdES: The digest algorithm used to hash ds:Reference.
     */
    val referenceDigestAlgorithm: DigestAlg? = null,

    /**
     * The encryption algorithm shall be automatically extracted from the signing token.
     */
    val encryptionAlgorithm: CryptoAlg? = signatureAlgorithm.encryptionAlgorithm,


    /**
     * The mask generation function
     */
    val maskGenerationFunction: MaskGenFunction? = signatureAlgorithm.maskGenFunction,

    val signatureLevelParameters: SignatureLevelParameters? = null,

    val signatureFormParameters: SignatureFormParameters? = null,

    val timestampParameters: TimestampParameters? = null


//    /**
//     * PAdES: The image information to be included.
//     */
//    private val imageParameters: RemoteSignatureImageParameters? = null
//
//    /**
//     * This variable defines an Id of a signature to be counter-signed
//     * Used only for `getDataToBeCounterSigned()` and `counterSignSignature()` methods
//     */
//    private val signatureIdToCounterSign: String? = null

)

@kotlinx.serialization.Serializable
data class SignatureLevelParameters(
    /**
     * This variable indicates the expected signature level
     */
    val signatureLevel: SignatureLevel,

    /**
     * The object representing the parameters related to B- level.
     */
    val bLevelParameters: BLevelParams? = null
)

@kotlinx.serialization.Serializable
data class SignatureFormParameters(
    // SignatureForm comes from the signature level
    // val signatureForm: SignatureForm,

    /**
     * ETSI Cades
     */
    val cadesSignatureFormParameters: CadesSignatureFormParameters? = null,

    /**
     * ETSI Pades PDF
     */
    val padesSignatureFormParameters: PadesSignatureFormParameters? = null,

    /**
     * Adobe PKCS7 PDF
     */
    val pkcs7SignatureFormParameters: Pkcs7SignatureFormParameters? = null,

    /**
     * ETSI Jades JSON
     */
    val jadesSignatureFormParameters: JadesSignatureFormParameters? = null,


//    val xadesSignatureFormParameters: XadesSignatureFormParameters? = null
)

@kotlinx.serialization.Serializable
data class JadesSignatureFormParameters(
    /**
     * JAdES JWS Serialization Type
     */
    val jwsSerializationType: JWSSerializationType? = null,

    /**
     * JAdES SigDMechanism for a DETACHED packaging
     */
//    private val sigDMechanism: SigDMechanism? = null

)

// adbe.pkcs7.detached
@kotlinx.serialization.Serializable
data class Pkcs7SignatureFormParameters(
    /**
     * The signature mode, according to the PDF spec
     */
    val mode: PdfSignatureMode? = PdfSignatureMode.APPROVAL,

    /**
     * This attribute allows to explicitly specify the SignerName (name for the Signature).
     * The person or authority signing the document.
     */
    val signerName: String? = null,


    /** The signature creation reason  */
    val reason: String? = null,

    /** The contact info  */
    val contactInfo: String? = null,

    /** The signer's location  */
    val location: String? = null,

    /**
     * Defines the preserved space for a signature context
     *
     * Default : 9472 (default value in pdfbox)
     */
    val signatureSize: Int? = 9472,

    /**
     * This attribute allows to override the used Filter for a Signature.
     *
     * Default value is Adobe.PPKLite
     */
    val signatureFilter: String? = "Adobe.PPKLite",

    /**
     * This attribute allows to override the used subFilter for a Signature.
     *
     * Default value is adbe.pkcs7.detached
     */
    val signatureSubFilter: String? = "adbe.pkcs7.detached",

    /**
     * This attribute is used to create visible signature in PAdES form
     */
//    val signatureImageParameters?: SignatureImageParameters = null,

    /**
     * This attribute allows to create a "certification signature". That allows to remove permission(s) in case of
     * future change(s).
     */
    val permission: CertificationPermission? = null,

    /**
     * Password used to encrypt a PDF
     */
    val passwordProtection: String? = null,

    /**
     * The time-zone used for signature creation
     *
     * Default: TimeZone.getDefault()
     */
//    val signingTimeZone: java.util.TimeZone =        java.util.TimeZone.getDefault(),


)

enum class PdfSignatureMode {
    CERTIFICATION, APPROVAL
}

@kotlinx.serialization.Serializable
data class PadesSignatureFormParameters(
    /** The signature creation reason  */
    val reason: String? = null,

    /** The contact info  */
    val contactInfo: String? = null,

    /** The signer's location  */
    val location: String? = null,

    /**
     * Defines the preserved space for a signature context
     *
     * Default : 9472 (default value in pdfbox)
     */
    val signatureSize: Int? = 9472,

    /**
     * This attribute allows to override the used Filter for a Signature.
     *
     * Default value is Adobe.PPKLite
     */
    val signatureFilter: String? = "Adobe.PPKLite",

    /**
     * This attribute allows to override the used subFilter for a Signature.
     *
     * Default value is ETSI.CAdES.detached
     */
    val signatureSubFilter: String? = "ETSI.CAdES.detached",

    /**
     * This attribute allows to explicitly specify the SignerName (name for the Signature).
     * The person or authority signing the document.
     */
    val signerName: String? = null,

    /**
     * This attribute is used to create visible signature in PAdES form
     */
//    val signatureImageParameters?: SignatureImageParameters = null,

    /**
     * This attribute allows to create a "certification signature". That allows to remove permission(s) in case of
     * future change(s).
     */
    val permission: CertificationPermission? = null,

    /**
     * Password used to encrypt a PDF
     */
    val passwordProtection: String? = null,

    /**
     * The time-zone used for signature creation
     *
     * Default: TimeZone.getDefault()
     */
//    val signingTimeZone: java.util.TimeZone =        java.util.TimeZone.getDefault(),


    /** Defines if the signature shall be created according ti ETSI EN 319 122  */
    val en319122: Boolean? = true,

    /** Content Hints type  */
    val contentHintsType: String? = null,

    /** Content Hints description  */
    val contentHintsDescription: String? = null,

    /** Content identifier prefix  */
    val contentIdentifierPrefix: String? = null,

    /** Content identifier suffix  */
    val contentIdentifierSuffix: String? = null

)

@kotlinx.serialization.Serializable
data class CadesSignatureFormParameters(

    /** Defines if the signature shall be created according ti ETSI EN 319 122  */
    val en319122: Boolean? = true,

    /** Content Hints type  */
    val contentHintsType: String? = null,

    /** Content Hints description  */
    val contentHintsDescription: String? = null,

    /** Content identifier prefix  */
    val contentIdentifierPrefix: String? = null,

    /** Content identifier suffix  */
    val contentIdentifierSuffix: String? = null

)

@kotlinx.serialization.Serializable
data class XadesSignatureFormParameters(
    /**
     * XAdES: The digest algorithm used to hash ds:Reference.
     */
    val referenceDigestAlgorithm: DigestAlg? = null
)

@kotlinx.serialization.Serializable
data class TimestampParameters(
    /**
     * This object represents the list of content timestamps to be added into the signature.
     */
    val contentTimestamps: List<Timestamp>? = null,

    /**
     * The object represents the parameters related to the content timestamp (Baseline-B)
     */
    val contentTimestampParameters: TimestampParameterSettings? = null,

    /**
     * The object represents the parameters related to the signature timestamp (Baseline-T)
     */
    val signatureTimestampParameters: TimestampParameterSettings? = null,

    /**
     * The object represents the parameters related to the archive timestamp (Baseline-LTA)
     */
    val archiveTimestampParameters: TimestampParameterSettings? = null,
)

@kotlinx.serialization.Serializable
data class BLevelParams(
    private val trustAnchorBPPolicy: Boolean? = true,

    /** The claimed signing time  */
    val signingDate: Instant? = Clock.System.now(),

    /** The claimed signer roles  */
    val claimedSignerRoles: List<String>? = null,

    /** Signature policy id  */
    val policyId: String? = null,

    /** Qualifier attribute for XAdES Identifier  */
//    private val policyQualifier: ObjectIdentifierQualifier? = null,

    /** The signature policy description  */
    val policyDescription: String? = null,

    /** The signature policy digest algorithm  */
    val policyDigestAlgorithm: DigestAlg? = null,

    /** The signature policy digest value  */
    @kotlinx.serialization.Serializable(with = Base64Serializer::class)
    val policyDigestValue: ByteArray? = null,

    /** The signature policy access URI  */
    val policySpuri: String? = null,

    /** Commitment type indications  */
//    private val commitmentTypeIndications: List<CommitmentTypeEnum>? = null,

    /** SignerLocation postal address  */
    val signerLocationPostalAddress: List<String>? = null,

    /** SignerLocation postal code  */
    val signerLocationPostalCode: String? = null,

    /** SignerLocation locality  */
    val signerLocationLocality: String? = null,

    /** SignerLocation state or province  */
    val signerLocationStateOrProvince: String? = null,

    /** SignerLocation country  */
    val signerLocationCountry: String? = null,

    /** SignerLocation street  */
    val signerLocationStreet: String? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as BLevelParams

        if (trustAnchorBPPolicy != other.trustAnchorBPPolicy) return false
        if (signingDate != other.signingDate) return false
        if (claimedSignerRoles != other.claimedSignerRoles) return false
        if (policyId != other.policyId) return false
        if (policyDescription != other.policyDescription) return false
        if (policyDigestAlgorithm != other.policyDigestAlgorithm) return false
        if (!policyDigestValue.contentEquals(other.policyDigestValue)) return false
        if (policySpuri != other.policySpuri) return false
        if (signerLocationPostalAddress != other.signerLocationPostalAddress) return false
        if (signerLocationPostalCode != other.signerLocationPostalCode) return false
        if (signerLocationLocality != other.signerLocationLocality) return false
        if (signerLocationStateOrProvince != other.signerLocationStateOrProvince) return false
        if (signerLocationCountry != other.signerLocationCountry) return false
        if (signerLocationStreet != other.signerLocationStreet) return false

        return true
    }

    override fun hashCode(): Int {
        var result = trustAnchorBPPolicy.hashCode()
        result = 31 * result + signingDate.hashCode()
        result = 31 * result + (claimedSignerRoles?.hashCode() ?: 0)
        result = 31 * result + (policyId?.hashCode() ?: 0)
        result = 31 * result + (policyDescription?.hashCode() ?: 0)
        result = 31 * result + (policyDigestAlgorithm?.hashCode() ?: 0)
        result = 31 * result + policyDigestValue.contentHashCode()
        result = 31 * result + (policySpuri?.hashCode() ?: 0)
        result = 31 * result + signerLocationPostalAddress.hashCode()
        result = 31 * result + (signerLocationPostalCode?.hashCode() ?: 0)
        result = 31 * result + (signerLocationLocality?.hashCode() ?: 0)
        result = 31 * result + (signerLocationStateOrProvince?.hashCode() ?: 0)
        result = 31 * result + (signerLocationCountry?.hashCode() ?: 0)
        result = 31 * result + (signerLocationStreet?.hashCode() ?: 0)
        return result
    }
}
