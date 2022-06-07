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
    private val signatureAlgorithm: SignatureAlg? = SignatureAlg.RSA_SHA256,

    /**
     * XAdES: The digest algorithm used to hash ds:SignedInfo.
     */
    val digestAlgorithm: DigestAlg? = signatureAlgorithm?.digestAlgorithm ?: DigestAlg.SHA256,

    /**
     * XAdES: The digest algorithm used to hash ds:Reference.
     */
    val referenceDigestAlgorithm: DigestAlg? = null,

    /**
     * The encryption algorithm shall be automatically extracted from the signing token.
     */
    val encryptionAlgorithm: CryptoAlg? = signatureAlgorithm?.encryptionAlgorithm ?: CryptoAlg.RSA,


    /**
     * The mask generation function
     */
    val maskGenerationFunction: MaskGenFunction? = signatureAlgorithm?.maskGenFunction,

    val signatureLevelParameters: SignatureLevelParameters? = null,

    val signatureFormParameters: SignatureFormParameters? = null,

//    val timestampParameters: TimestampParameters? = null


//    /**
//     * This variable defines an Id of a signature to be counter-signed
//     * Used only for `getDataToBeCounterSigned()` and `counterSignSignature()` methods
//     */
//    private val signatureIdToCounterSign: String? = null

) {
    fun getSignatureAlgorithm(): SignatureAlg? {
        return signatureAlgorithm
    }
}

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
     * The signature mode, according to the PDF spec. Either needs to be APPROVAL or CERTIFICATION.
     *
     * - CERTIFICATION can only be applied once to a PDF document. It acts like a seal, which typically is organization or department wide.
     * A blue bar will appear with name of the signer, the company and the CA that issued the Certificate
     * - APPROVAL can be applied multiple times. This is what typically is being used for people signing the document. It is comparable to a user signing a paper based document.
     * The signature shows the name and additional information. Optionally showing an image of the signature. Clickable to show more information
     */
    val mode: PdfSignatureMode = PdfSignatureMode.APPROVAL,

    /**
     * This attribute allows to explicitly specify the SignerName (name for the entity signing).
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
     * Defines the preserved space for a signature context. Only change if you know what you are doing
     *
     * Default : 9472 (default value in pdfbox)
     */
    val signatureSize: Int? = 9472,

    /**
     * This attribute allows to override the used Filter for a Signature.
     *
     * Default value is Adobe.PPKLite
     */
    val signatureFilter: String? = PdfSignatureFilter.ADOBE_PPKLITE.specName,

    /**
     * This attribute allows to override the used subFilter for a Signature.
     *
     * Default value is adbe.pkcs7.detached
     */
    val signatureSubFilter: String? = PdfSignatureSubFilter.ADBE_PKCS7_DETACHED.specName,

    /**
     * This attribute is used to create visible signature
     */
    val visualSignatureParameters: VisualSignatureParameters? = null,

    /**
     * This attribute allows to set permissions in case of a "certification signature". That allows to protect for
     * future change(s).
     */
    val certificationPermission: CertificationPermission? = null,

    /**
     * Password used to encrypt a PDF
     */
    val passwordProtection: String? = null,

    /**
     * The time-zone used for signature creation
     *
     * Default: Default timezone of the system
     */
    val signingTimeZone: String? = null


)

enum class PdfSignatureMode {
    CERTIFICATION, APPROVAL
}

@kotlinx.serialization.Serializable
data class PadesSignatureFormParameters(
    /**
     * The signature mode, according to the PDF spec. Either needs to be APPROVAL or CERTIFICATION.
     *
     * - CERTIFICATION can only be applied once to a PDF document. It acts like a seal, which typically is organization or department wide.
     * A blue bar will appear with name of the signer, the company and the CA that issued the Certificate
     * - APPROVAL can be applied multiple times. This is what typically is being used for people signing the document. It is comparable to a user signing a paper based document.
     * The signature shows the name and additional information. Optionally showing an image of the signature. Clickable to show more information
     */
    val mode: PdfSignatureMode = PdfSignatureMode.APPROVAL,

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
    val signatureFilter: String? = PdfSignatureFilter.ADOBE_PPKLITE.specName,

    /**
     * This attribute allows to override the used subFilter for a Signature.
     *
     * Default value is ETSI.CAdES.detached
     */
    val signatureSubFilter: String? = PdfSignatureSubFilter.ETSI_CADES_DETACHED.specName,


    /**
     * This attribute is used to create visible signature in PAdES form
     */
    val visualSignatureParameters: VisualSignatureParameters? = null,

    /**
     * This attribute allows to create a "certification signature". That allows to remove permission(s) in case of
     * future change(s).
     */
    val certificationPermission: CertificationPermission? = null,

    /**
     * Password used to encrypt a PDF
     */
    val passwordProtection: String? = null,

    /**
     * The time-zone used for signature creation
     *
     * Default: Timezone of the signing system
     */
    val signingTimeZone: String? = null,


    /** Defines if the signature shall be created according ti ETSI EN 319 122  */
    val en319122: Boolean? = true,

  /*  *//** Content Hints type  *//*
    val contentHintsType: String? = null,

    *//** Content Hints description  *//*
    val contentHintsDescription: String? = null,

    *//** Content identifier prefix  *//*
    val contentIdentifierPrefix: String? = null,

    *//** Content identifier suffix  *//*
    val contentIdentifierSuffix: String? = null*/

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
    val tsaUrl: String,
    /**
     * This object represents the list of content timestamps to be added into the signature.
     */
    val contentTimestamps: List<Timestamp>? = null,

    /**
     * The object represents the parameters related to the content timestamp (Baseline-B)
     */
    val baselineBContentTimestampParameters: TimestampParameterSettings? = null,

    /**
     * The object represents the parameters related to the signature timestamp (Baseline-T)
     */
    val baselineTSignatureTimestampParameters: TimestampParameterSettings? = null,

    /**
     * The object represents the parameters related to the archive timestamp (Baseline-LTA)
     */
    val baselineLTAArchiveTimestampParameters: TimestampParameterSettings? = null,
)

@kotlinx.serialization.Serializable
data class BLevelParams(
    val trustAnchorBPPolicy: Boolean? = true,

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


@kotlinx.serialization.Serializable
data class VisualSignatureParameters(

    /**
     * This variable contains the image to use (company logo,...)
     */
    val image: OrigData? = null,

    /**
     * This variable defines a `SignatureFieldParameters` like field positions and dimensions
     */
    val fieldParameters: VisualSignatureFieldParameters? = null,

    /**
     * This variable defines a percent to zoom the image (100% means no scaling).
     * Note: This does not touch zooming of the text representation.
     */
    val zoom: Int = NO_SCALING,

    /**
     * This variable defines the color of the image
     */
    val backgroundColor: String? = null,

    /**
     * This variable defines the DPI of the image
     */
    val dpi: Int? = null,

    /**
     * Use rotation on the PDF page, where the visual signature will be
     */
    val rotation: VisualSignatureRotation? = null,

    /**
     * Horizontal alignment of the visual signature on the pdf page
     */

    val alignmentHorizontal: VisualSignatureAlignmentHorizontal? = VisualSignatureAlignmentHorizontal.NONE,

    /**
     * Vertical alignment of the visual signature on the pdf page
     */
    val alignmentVertical: VisualSignatureAlignmentVertical? = VisualSignatureAlignmentVertical.NONE,

    /**
     * Defines the image scaling behavior within a signature field with a fixed size
     *
     * DEFAULT : ImageScaling.STRETCH (stretches the image in both directions to fill the signature field)
     */
    val imageScaling: ImageScaling? = ImageScaling.STRETCH,

    /**
     * This variable is use to defines the text to generate on the image
     */
    val textParameters: VisualSignatureTextParameters? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as VisualSignatureParameters

        if (image != other.image) return false
        if (fieldParameters != other.fieldParameters) return false
        if (zoom != other.zoom) return false
        if (backgroundColor != other.backgroundColor) return false
        if (dpi != other.dpi) return false
        if (rotation != other.rotation) return false
        if (alignmentHorizontal != other.alignmentHorizontal) return false
        if (alignmentVertical != other.alignmentVertical) return false
        if (imageScaling != other.imageScaling) return false
        if (textParameters != other.textParameters) return false

        return true
    }

    override fun hashCode(): Int {
        var result = image?.hashCode() ?: 0
        result = 31 * result + (fieldParameters?.hashCode() ?: 0)
        result = 31 * result + zoom
        result = 31 * result + (backgroundColor?.hashCode() ?: 0)
        result = 31 * result + (dpi ?: 0)
        result = 31 * result + (rotation?.hashCode() ?: 0)
        result = 31 * result + (alignmentHorizontal?.hashCode() ?: 0)
        result = 31 * result + (alignmentVertical?.hashCode() ?: 0)
        result = 31 * result + (imageScaling?.hashCode() ?: 0)
        result = 31 * result + (textParameters?.hashCode() ?: 0)
        return result
    }
}

@kotlinx.serialization.Serializable
data class VisualSignatureFieldParameters(
    /** Signature field id/name (optional)  */
    val fieldId: String? = null,

    /** Page number where the signature field is added  */
    val page: Int = DEFAULT_FIRST_PAGE,

    /** Coordinate X where to add the signature field (origin is top/left corner)  */
    val originX: Float = 0f,

    /** Coordinate Y where to add the signature field (origin is top/left corner)  */
    val originY: Float = 0f,

    /** Signature field width  */
    val width: Float = 0f,

    /** Signature field height  */
    val height: Float = 0f
)

/**
 * This class allows to custom text generation in the PAdES visible signature
 *
 */
@kotlinx.serialization.Serializable
data class VisualSignatureTextParameters(
    /**
     * This variable allows to add signer name on the image (by default, LEFT)
     */
    val signerTextPosition: SignerTextPosition = SignerTextPosition.LEFT,

    /**
     * This variable defines the image from text vertical alignment in connection
     * with the image<br></br>
     * <br></br>
     * It has effect when the [SignerPosition][SignerTextPosition] is
     * [LEFT][SignerTextPosition.LEFT] or [ RIGHT][SignerTextPosition.RIGHT]
     */
    val signerTextVerticalAlignment: SignerTextVerticalAlignment = SignerTextVerticalAlignment.MIDDLE,

    /**
     * This variable set the more line text horizontal alignment
     */
    val signerTextHorizontalAlignment: SignerTextHorizontalAlignment = SignerTextHorizontalAlignment.LEFT,

    /**
     * This variable defines the text to sign
     */
    val text: String,

    /**
     * This variable defines the font to use
     * (default is PTSerifRegular)
     */
    val font: String? = null,

    /**
     * This variable defines how the given text should be wrapped within the signature field's box
     *
     * Default : TextWrapping.FONT_BASED - the text is computed based on the `dssFont` configuration
     */
    val textWrapping: TextWrapping = TextWrapping.FONT_BASED,

    /**
     * This variable defines a padding in pixels to bound text around
     * (default is 5)
     */
    val padding: Float = DEFAULT_PADDING,

    /**
     * This variable defines the text color to use
     * (default is BLACK)
     * (PAdES visual appearance: allow null as text color, preventing graphic operators)
     */
    val textColor: String? = DEFAULT_TEXT_COLOR,

    /**
     * This variable defines the background of a text bounding box
     */
    val backgroundColor: String? = DEFAULT_BACKGROUND_COLOR
)

const val DEFAULT_BACKGROUND_COLOR: String = "WHITE"

/** The default padding (5 pixels)  */
const val DEFAULT_PADDING = 5f

/** The default text color (black)  */
const val DEFAULT_TEXT_COLOR: String = "BLACK"
const val NO_SCALING: Int = 100
const val DEFAULT_DPI = 96
const val DEFAULT_FIRST_PAGE = 1
