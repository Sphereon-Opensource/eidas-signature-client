package com.sphereon.vdx.pkcs7

import com.sphereon.vdx.ades.model.PdfSignatureMode
import com.sphereon.vdx.pkcs7.support.CMSProcessableInputStream
import com.sphereon.vdx.pkcs7.support.SigUtils
import eu.europa.esig.dss.alert.ExceptionOnStatusAlert
import eu.europa.esig.dss.alert.StatusAlert
import eu.europa.esig.dss.alert.status.MessageStatus
import eu.europa.esig.dss.cades.CMSUtils
import eu.europa.esig.dss.cades.signature.CustomContentSigner
import eu.europa.esig.dss.enumerations.DigestAlgorithm
import eu.europa.esig.dss.enumerations.SignatureLevel
import eu.europa.esig.dss.enumerations.TimestampType
import eu.europa.esig.dss.model.*
import eu.europa.esig.dss.pades.PAdESCommonParameters
import eu.europa.esig.dss.pades.SignatureFieldParameters
import eu.europa.esig.dss.pades.SignatureImageParameters
import eu.europa.esig.dss.pdf.AnnotationBox
import eu.europa.esig.dss.pdf.IPdfObjFactory
import eu.europa.esig.dss.pdf.PdfAnnotation
import eu.europa.esig.dss.pdf.PdfDocumentReader
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory
import eu.europa.esig.dss.pdf.encryption.DSSSecureRandomProvider
import eu.europa.esig.dss.pdf.encryption.SecureRandomProvider
import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder
import eu.europa.esig.dss.pdf.modifications.PdfDifferencesFinder
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDocumentReader
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxSignatureDrawer
import eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer.PdfBoxNativeSignatureDrawerFactory
import eu.europa.esig.dss.pdf.visible.SignatureDrawer
import eu.europa.esig.dss.pdf.visible.SignatureFieldBoxBuilder
import eu.europa.esig.dss.signature.AbstractSignatureService
import eu.europa.esig.dss.signature.SignatureExtension
import eu.europa.esig.dss.signature.SigningOperation
import eu.europa.esig.dss.spi.DSSUtils
import eu.europa.esig.dss.validation.CertificateVerifier
import eu.europa.esig.dss.validation.timestamp.TimestampToken
import mu.KotlinLogging
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.asn1.cms.Attributes
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.cms.*
import org.bouncycastle.tsp.TSPException
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.SecureRandom
import java.util.*

data class MergeResult(val content: ByteArrayInputStream, val dataToSign: ByteArray)

class PKCS7Service(
    certificateVerifier: CertificateVerifier?,
    private var pdfObjFactory: IPdfObjFactory = ServiceLoaderPdfObjFactory(),
    private val pkcs7CMSSignedDataBuilder: PKCS7CMSSignedDataBuilder = PKCS7CMSSignedDataBuilder(certificateVerifier),
) :
    AbstractSignatureService<PKCS7SignatureParameters, TimestampParameters>(
        certificateVerifier
    ) {

    private val signatureDrawerFactory = PdfBoxNativeSignatureDrawerFactory()
    private var secureRandomProvider: SecureRandomProvider? = null
    private val alertOnSignatureFieldOverlap: StatusAlert = ExceptionOnStatusAlert()
    private val alertOnSignatureFieldOutsidePageDimensions: StatusAlert = ExceptionOnStatusAlert()
    private var pdfDifferencesFinder: PdfDifferencesFinder = DefaultPdfDifferencesFinder()

    companion object {
        private val logger = KotlinLogging.logger {}
    }

    @Throws(DSSException::class)
    override fun getDataToSign(toSignDocument: DSSDocument, parameters: PKCS7SignatureParameters): ToBeSigned {
        Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!")
        Objects.requireNonNull(parameters, "SignatureParameters cannot be null!")
        assertSignaturePossible(toSignDocument)
        assertSigningCertificateValid(parameters)
        val documentReader = PdfBoxDocumentReader(toSignDocument, parameters.passwordProtection)
        documentReader.checkDocumentPermissions()
        val result = mergeSignature(parameters, DSSUtils.EMPTY_BYTE_ARRAY, documentReader, toSignDocument)
        return ToBeSigned(result.dataToSign)
    }


    override fun signDocument(toSignDocument: DSSDocument, parameters: PKCS7SignatureParameters, signatureValue: SignatureValue): DSSDocument {
        assertSigningCertificateValid(parameters)

        var signedDocument: DSSDocument = signDetached(toSignDocument, parameters, signatureValue)
        val signatureLevel = parameters.signatureLevel
        val extension: SignatureExtension<PKCS7SignatureParameters>? = this.getExtensionProfile(signatureLevel)
        if (signatureLevel != SignatureLevel.PKCS7_B && signatureLevel != SignatureLevel.PKCS7_T && extension != null) {
            signedDocument = extension.extendSignatures(signedDocument, parameters)
        }

        parameters.reinit()

        signedDocument.name = this.getFinalFileName(toSignDocument, SigningOperation.SIGN, SignatureLevel.CAdES_A)
            .replace("-cades-a", "")
            .plus(".pdf")
        return signedDocument
    }

    private fun signDetached(toSignDocument: DSSDocument, parameters: PKCS7SignatureParameters, signatureValue: SignatureValue): DSSDocument {
        val documentReader = PdfBoxDocumentReader(toSignDocument, parameters.passwordProtection)
        try {
            documentReader.checkDocumentPermissions()
            val result = mergeSignature(parameters, signatureValue.value, documentReader, toSignDocument)
            val output: DSSDocument = InMemoryDocument(result.content)
            output.mimeType = MimeType.PDF
            return output
        } catch (e: Exception) {
            documentReader.close()
            throw e
        }
    }


    private fun mergeSignature(
        parameters: PKCS7SignatureParameters,
        signatureContent: ByteArray,
        documentReader: PdfBoxDocumentReader,
        toSignDocument: DSSDocument
    ): MergeResult {
        val outputStream = ByteArrayOutputStream()

        // create signature dictionary
        val signature = PDSignature()
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED)
        signature.name = parameters.signerName
        signature.location = parameters.location
        signature.reason = parameters.reason ?: "E-signed by ${parameters.signerName}"
        signature.contactInfo = parameters.contactInfo
        val certify = parameters.signatureMode == PdfSignatureMode.CERTIFICATION

        val imageParameters = parameters.imageParameters
        val signatureLog = String.format(
            "%s %s signature: %s, %s, %s", if (imageParameters.isEmpty) "Invisible" else "Visible",
            if (certify) "certify" else "approval", signature.contactInfo, signature.location, signature.reason
        )
        logger.debug("Start signing {}", signatureLog)

        if (certify) {
            handleCertify(documentReader, toSignDocument, signatureLog, signature)
        }

        // the signing date, needed for valid signature
        val calendar = Calendar.getInstance()
        calendar.time = parameters.signingDate
        calendar.timeZone = parameters.signingTimeZone
        signature.signDate = calendar

        val options = SignatureOptions()
        options.preferredSignatureSize = parameters.contentSize

        if (!imageParameters.isEmpty) {
            val signatureOptions = SignatureOptions()
            val signatureDrawer = loadSignatureDrawer(imageParameters) as PdfBoxSignatureDrawer
            signatureDrawer.init(imageParameters, documentReader.pdDocument, signatureOptions)
            //                if (pdSignatureField == null) { TODO find existing signature field?
            this.getVisibleSignatureFieldBoxPosition(signatureDrawer, documentReader, imageParameters.fieldParameters)
            //                }
            signatureDrawer.draw()
        }

        documentReader.pdDocument.addSignature(signature, options)
        if (documentReader.pdDocument.documentId == null) {
            documentReader.pdDocument.documentId = parameters.signingDate.time
        }

        if (documentReader.pdDocument.isEncrypted) {
            val secureRandom: SecureRandom = this.getSecureRandomProvider(parameters)!!.secureRandom
            documentReader.pdDocument.encryption.securityHandler.setCustomSecureRandom(secureRandom)
        }

        val externalSigning = documentReader.pdDocument.saveIncrementalForExternalSigning(outputStream)
        val inputStream = externalSigning.content

        val signatureAlgorithm = parameters.signatureAlgorithm
        val customContentSigner = CustomContentSigner(signatureAlgorithm.jceId, signatureContent)
        val cmsSignedData = generateCMSData(parameters, inputStream, customContentSigner)
        val dataToSign = customContentSigner.outputStream.toByteArray()
        externalSigning.setSignature(cmsSignedData.encoded)

        val toByteArray = outputStream.toByteArray()
        logger.debug("End signing {}", signatureLog)
        return MergeResult(ByteArrayInputStream(toByteArray), dataToSign)
    }

    private fun handleCertify(
        documentReader: PdfBoxDocumentReader,
        toSignDocument: DSSDocument,
        signatureLog: String,
        signature: PDSignature
    ) {
        // Optional: certify
        // can be done only if version is at least 1.5 and if not already set
        // doing this on a PDF/A-1b file fails validation by Adobe preflight (PDFBOX-3821)
        // PDF/A-1b requires PDF version 1.4 max, so don't increase the version on such files.
        // We create an approval signature when already certified before or at lower than 1.5 versions.

        // TODO: 03/09/2020 Move to general location, as this is applicable to the whole stamper functionality
        val mdAccessPermissions = SigUtils.getMDPPermission(documentReader.pdDocument)
        if (mdAccessPermissions != 0) {
            logger.warn(
                "Not certifying although mode was certify, because this is not the first signature for {}, {}", toSignDocument.name,
                signatureLog
            )
        } else if (documentReader.pdDocument.version < 1.5f) {
            logger.warn(
                "Not certifying although mode was certify, because document version {} for {}, {}", documentReader.pdDocument.version,
                toSignDocument.name, signatureLog
            )
        } else {
            SigUtils.setMDPPermission(documentReader.pdDocument, signature, 2)
        }
    }

    private fun generateCMSData(
        parameters: PKCS7SignatureParameters,
        inputStream: InputStream,
        customContentSigner: CustomContentSigner
    ): CMSSignedData {
        val signatureLevel = parameters.signatureLevel
        Objects.requireNonNull(signatureLevel, "SignatureLevel must be defined!")

        val signerInfoGeneratorBuilder: SignerInfoGeneratorBuilder =
            this.pkcs7CMSSignedDataBuilder.getSignerInfoGeneratorBuilder(parameters, inputStream)
        val generator: CMSSignedDataGenerator = this.pkcs7CMSSignedDataBuilder.createCMSSignedDataGenerator(
            parameters,
            customContentSigner,
            signerInfoGeneratorBuilder,
            null as CMSSignedData?
        )
        val content = CMSProcessableInputStream(inputStream)
        var cmsSignedData = CMSUtils.generateCMSSignedData(generator, content, true)
        if (signatureLevel != SignatureLevel.PKCS7_B) {
            //cmsSignedData = addSignedTimeStamp(cmsSignedData)
            val pkcS7BaselineT = PKCS7BaselineT(tspSource, certificateVerifier, pdfObjFactory)
            cmsSignedData = pkcS7BaselineT.extendCMSSignatures(cmsSignedData, parameters)
        }
        return cmsSignedData
    }

    private fun addSignedTimeStamp(signedData: CMSSignedData): CMSSignedData {
        val signerStore: SignerInformationStore = signedData.getSignerInfos()
        val newSigners: MutableList<SignerInformation> = ArrayList()

        for (signer in signerStore.signers) {
            // This adds a timestamp to every signer (into his unsigned attributes) in the signature.
            newSigners.add(signTimeStamp(signer))
        }

        // Because new SignerInformation is created, new SignerInfoStore has to be created
        // and also be replaced in signedData. Which creates a new signedData object.

        // Because new SignerInformation is created, new SignerInfoStore has to be created
        // and also be replaced in signedData. Which creates a new signedData object.
        return CMSSignedData.replaceSigners(signedData, SignerInformationStore(newSigners))

    }

    private fun signTimeStamp(signer: SignerInformation): SignerInformation {
        val digestAlgorithm = DigestAlgorithm.SHA256 // FIXME
        val unsignedAttributes = signer.unsignedAttributes
        var vector = ASN1EncodableVector()
        if (unsignedAttributes != null) {
            vector = unsignedAttributes.toASN1EncodableVector()
        }

        val token = tspSource.getTimeStampResponse(digestAlgorithm, signer.signature)
        val oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken
        val signatureTimeStamp: ASN1Encodable = Attribute(
            oid,
            DERSet(ASN1Primitive.fromByteArray(token.bytes))
        )

        vector.add(signatureTimeStamp)
        val signedAttributes = Attributes(vector)

        // There is no other way changing the unsigned attributes of the signer information.
        // result is never null, new SignerInformation always returned,
        // see source code of replaceUnsignedAttributes

        // There is no other way changing the unsigned attributes of the signer information.
        // result is never null, new SignerInformation always returned,
        // see source code of replaceUnsignedAttributes
        return SignerInformation.replaceUnsignedAttributes(signer, AttributeTable(signedAttributes))
    }

    private fun loadSignatureDrawer(imageParameters: SignatureImageParameters?): SignatureDrawer {
        return signatureDrawerFactory.getSignatureDrawer(imageParameters)
    }

    private fun getVisibleSignatureFieldBoxPosition(
        signatureDrawer: SignatureDrawer?,
        documentReader: PdfDocumentReader,
        fieldParameters: SignatureFieldParameters
    ): AnnotationBox? {
        var signatureFieldAnnotation: AnnotationBox? = this.buildSignatureFieldBox(signatureDrawer)
        if (signatureFieldAnnotation != null) {
            val pageBox = documentReader.getPageBox(fieldParameters.page)
            documentReader.getPageRotation(fieldParameters.page)
            signatureFieldAnnotation = this.toPdfPageCoordinates(signatureFieldAnnotation, pageBox)
            this.assertSignatureFieldPositionValid(signatureFieldAnnotation!!, documentReader, fieldParameters)
        }
        return signatureFieldAnnotation
    }

    private fun toPdfPageCoordinates(fieldAnnotationBox: AnnotationBox, pageBox: AnnotationBox): AnnotationBox? {
        return fieldAnnotationBox.toPdfPageCoordinates(pageBox.height)
    }


    private fun assertSignatureFieldPositionValid(annotationBox: AnnotationBox, reader: PdfDocumentReader, parameters: SignatureFieldParameters) {
        reader.getPageRotation(parameters.page)
        val pageBox = reader.getPageBox(parameters.page)
        this.checkSignatureFieldAgainstPageDimensions(annotationBox, pageBox)
        val pdfAnnotations = reader.getPdfAnnotations(parameters.page)
        this.checkSignatureFieldBoxOverlap(annotationBox, pdfAnnotations)
    }


    private fun checkSignatureFieldAgainstPageDimensions(signatureFieldBox: AnnotationBox, pageBox: AnnotationBox) {
        if (signatureFieldBox.minX < pageBox.minX || signatureFieldBox.maxX > pageBox.maxX || signatureFieldBox.minY < pageBox.minY || signatureFieldBox.maxY > pageBox.maxY) {
            this.alertOnSignatureFieldOutsidePageDimensions(signatureFieldBox, pageBox)
        }
    }

    private fun checkSignatureFieldBoxOverlap(signatureFieldBox: AnnotationBox?, pdfAnnotations: List<PdfAnnotation?>?) {
        if (pdfDifferencesFinder.isAnnotationBoxOverlapping(signatureFieldBox, pdfAnnotations)) {
            alertOnSignatureFieldOverlap()
        }
    }

    private fun alertOnSignatureFieldOverlap() {
        val status = MessageStatus()
        status.message = "The new signature field position overlaps with an existing annotation!"
        this.alertOnSignatureFieldOverlap.alert(status)
    }

    private fun alertOnSignatureFieldOutsidePageDimensions(signatureFieldBox: AnnotationBox, pageBox: AnnotationBox) {
        val status = MessageStatus()
        status.message = String.format(
            "The new signature field position is outside the page dimensions! Signature Field : [minX=%s, maxX=%s, minY=%s, maxY=%s], Page : [minX=%s, maxX=%s, minY=%s, maxY=%s]",
            signatureFieldBox.minX,
            signatureFieldBox.maxX,
            signatureFieldBox.minY,
            signatureFieldBox.maxY,
            pageBox.minX,
            pageBox.maxX,
            pageBox.minY,
            pageBox.maxY
        )
        alertOnSignatureFieldOutsidePageDimensions.alert(status)
    }

    private fun buildSignatureFieldBox(signatureDrawer: SignatureDrawer?): AnnotationBox? {
        if (signatureDrawer is SignatureFieldBoxBuilder) {
            val signatureFieldBoxBuilder = signatureDrawer as SignatureFieldBoxBuilder
            val signatureFieldBox = signatureFieldBoxBuilder.buildSignatureFieldBox()
            if (signatureFieldBox != null) {
                return signatureFieldBox.annotationBox
            }
        }
        if (logger.isDebugEnabled) {
            logger.debug("The used SignatureDrawer shall be an instance of VisibleSignatureFieldBoxBuilder in order to verify a SignatureField position!")
        }
        return null
    }

    private fun assertSignaturePossible(toSignDocument: DSSDocument) {
        require(toSignDocument !is DigestDocument) { "DigestDocument cannot be used for PDF-PKCS7!" }
    }


    override fun extendDocument(dssDocument: DSSDocument, parameters: PKCS7SignatureParameters): DSSDocument {
        throw java.lang.UnsupportedOperationException(String.format("Unsupported signature format '%s' for extension.", parameters.signatureLevel))
    }


    override fun getContentTimestamp(toSignDocument: DSSDocument, parameters: PKCS7SignatureParameters): TimestampToken {
        assertSignaturePossible(toSignDocument)
        val pdfSignatureService = pdfObjFactory.newContentTimestampService()
        val digestAlgorithm = parameters.contentTimestampParameters.digestAlgorithm
        val messageDigest = pdfSignatureService.digest(toSignDocument, parameters)
        val timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, messageDigest)

        return try {
            TimestampToken(timeStampResponse.bytes, TimestampType.CONTENT_TIMESTAMP)
        } catch (exception: IOException) {
            throw DSSException("Cannot obtain the content timestamp", exception)
        } catch (exception: CMSException) {
            throw DSSException("Cannot obtain the content timestamp", exception)
        } catch (exception: TSPException) {
            throw DSSException("Cannot obtain the content timestamp", exception)
        }
    }

    private fun getSecureRandomProvider(parameters: PAdESCommonParameters): SecureRandomProvider? {
        if (this.secureRandomProvider == null) {
            this.secureRandomProvider = DSSSecureRandomProvider(parameters)
        }
        return this.secureRandomProvider
    }

    private fun getExtensionProfile(signatureLevel: SignatureLevel): SignatureExtension<PKCS7SignatureParameters>? {
        Objects.requireNonNull(signatureLevel, "SignatureLevel must be defined!")
        return when (signatureLevel) {
            SignatureLevel.PKCS7_B -> null
            SignatureLevel.PKCS7_T -> PKCS7BaselineT(tspSource, certificateVerifier, pdfObjFactory)
            SignatureLevel.PKCS7_LT -> PKCS7BaselineLT(
                tspSource,
                certificateVerifier,
                pdfObjFactory
            )
            SignatureLevel.PKCS7_LTA -> PKCS7BaselineLTA(
                tspSource,
                certificateVerifier,
                pdfObjFactory
            )
            else -> throw UnsupportedOperationException(String.format("Unsupported signature format '%s' for extension.", signatureLevel))
        }
    }

}
