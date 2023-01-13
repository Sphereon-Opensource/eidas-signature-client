package com.sphereon.vdx.pkcs7

import com.sphereon.vdx.ades.model.PdfSignatureMode
import com.sphereon.vdx.pkcs7.support.SigUtils
import eu.europa.esig.dss.alert.ExceptionOnStatusAlert
import eu.europa.esig.dss.alert.StatusAlert
import eu.europa.esig.dss.alert.status.MessageStatus
import eu.europa.esig.dss.cades.CMSUtils
import eu.europa.esig.dss.cades.signature.CustomContentSigner
import eu.europa.esig.dss.enumerations.SignatureLevel
import eu.europa.esig.dss.enumerations.TimestampType
import eu.europa.esig.dss.model.*
import eu.europa.esig.dss.pades.SignatureFieldParameters
import eu.europa.esig.dss.pades.SignatureImageParameters
import eu.europa.esig.dss.pdf.AnnotationBox
import eu.europa.esig.dss.pdf.IPdfObjFactory
import eu.europa.esig.dss.pdf.PdfAnnotation
import eu.europa.esig.dss.pdf.PdfDocumentReader
import eu.europa.esig.dss.pdf.PdfModificationDetectionUtils
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDocumentReader
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxSignatureDrawer
import eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer.PdfBoxNativeSignatureDrawerFactory
import eu.europa.esig.dss.pdf.visible.SignatureDrawer
import eu.europa.esig.dss.pdf.visible.SignatureFieldBoxBuilder
import eu.europa.esig.dss.signature.AbstractSignatureService
import eu.europa.esig.dss.signature.SigningOperation
import eu.europa.esig.dss.spi.DSSUtils
import eu.europa.esig.dss.validation.CertificateVerifier
import eu.europa.esig.dss.validation.timestamp.TimestampToken
import mu.KotlinLogging
import org.apache.pdfbox.pdmodel.encryption.AccessPermission
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions
import org.bouncycastle.cms.*
import org.bouncycastle.tsp.TSPException
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.*

class PKCS7Service(
    certificateVerifier: CertificateVerifier?,
    private var pdfObjFactory: IPdfObjFactory = ServiceLoaderPdfObjFactory(),
    private val pkcs7CMSSignedDataBuilder: PKCS7CMSSignedDataBuilder = PKCS7CMSSignedDataBuilder(certificateVerifier),
) :
    AbstractSignatureService<PKCS7SignatureParameters, TimestampParameters>(
        certificateVerifier
    ) {

    private val signatureDrawerFactory = PdfBoxNativeSignatureDrawerFactory()

    private val alertOnSignatureFieldOverlap: StatusAlert = ExceptionOnStatusAlert()
    private val alertOnSignatureFieldOutsidePageDimensions: StatusAlert = ExceptionOnStatusAlert()

    companion object {
        private val logger = KotlinLogging.logger {}
    }

    @Throws(DSSException::class)
    override fun getDataToSign(toSignDocument: DSSDocument, parameters: PKCS7SignatureParameters): ToBeSigned {
        Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!")
        Objects.requireNonNull(parameters, "SignatureParameters cannot be null!")
        assertSignaturePossible(toSignDocument)
        assertSigningCertificateValid(parameters)
        val signatureAlgorithm = parameters.signatureAlgorithm
        val customContentSigner = CustomContentSigner(signatureAlgorithm.jceId)

        val documentReader = PdfBoxDocumentReader(toSignDocument, parameters.passwordProtection)
        documentReader.checkDocumentPermissions()
        ByteArrayOutputStream().use { outputStream ->
            val messageDigest = signAndReturnDigest(parameters, DSSUtils.EMPTY_BYTE_ARRAY, documentReader, toSignDocument, outputStream)
            val signerInfoGeneratorBuilder: SignerInfoGeneratorBuilder =
                this.pkcs7CMSSignedDataBuilder.getSignerInfoGeneratorBuilder(parameters, messageDigest)
            val generator: CMSSignedDataGenerator = this.pkcs7CMSSignedDataBuilder.createCMSSignedDataGenerator(
                parameters,
                customContentSigner,
                signerInfoGeneratorBuilder,
                null as CMSSignedData?
            )
            val content = CMSProcessableByteArray(messageDigest)
            CMSUtils.generateDetachedCMSSignedData(generator, content)
            val dataToSign = customContentSigner.outputStream.toByteArray()
            return ToBeSigned(dataToSign)
        }
    }

    override fun signDocument(toSignDocument: DSSDocument, parameters: PKCS7SignatureParameters, signatureValue: SignatureValue): DSSDocument {
        assertSigningCertificateValid(parameters)

        val signature: DSSDocument = signDetached(toSignDocument, parameters, signatureValue)
        parameters.reinit()
        signature.name = this.getFinalFileName(toSignDocument, SigningOperation.SIGN, SignatureLevel.CAdES_A)
            .replace("-cades-a", "")
            .plus(".pdf")
        return signature
    }

    private fun signDetached(toSignDocument: DSSDocument, parameters: PKCS7SignatureParameters, signatureValue: SignatureValue): DSSDocument {
        val baos = ByteArrayOutputStream()
        val documentReader = PdfBoxDocumentReader(toSignDocument, parameters.passwordProtection)
        try {
            documentReader.checkDocumentPermissions()
            signAndReturnDigest(parameters, signatureValue.value, documentReader, toSignDocument, baos)
            val output: DSSDocument = InMemoryDocument(baos.toByteArray())
            output.mimeType = MimeType.PDF
            return output
        } catch (e: Exception) {
            documentReader.close()
            throw e
        } finally {
            baos.close()
        }
    }

    private fun signAndReturnDigest(
        parameters: PKCS7SignatureParameters,
        signatureContent: ByteArray,
        documentReader: PdfBoxDocumentReader,
        toSignDocument: DSSDocument,
        baos: ByteArrayOutputStream
    ): ByteArray {
        val digest = DSSUtils.getMessageDigest(parameters.digestAlgorithm)
        val signatureInterface = SignatureInterface { content ->
            val b = ByteArray(4096)
            var count: Int
            while (content.read(b).also { count = it } > 0) {
                digest.update(b, 0, count)
            }
            signatureContent
        }

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
        logger.info("Start signing {}", signatureLog)

        if (certify) {
            // Optional: certify
            // can be done only if version is at least 1.5 and if not already set
            // doing this on a PDF/A-1b file fails validation by Adobe preflight (PDFBOX-3821)
            // PDF/A-1b requires PDF version 1.4 max, so don't increase the version on such files.
            // We create an approval signature when already certified before or at lower than 1.5 versions.
            val accessPermissions: AccessPermission = documentReader.pdDocument.currentAccessPermission
            if (accessPermissions.permissionBytes != 0) {
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

        // the signing date, needed for valid signature
        signature.signDate = Calendar.getInstance()
        if (!imageParameters.isEmpty) {
            val signatureOptions = SignatureOptions()
            val signatureDrawer = loadSignatureDrawer(imageParameters) as PdfBoxSignatureDrawer
            signatureDrawer.init(imageParameters, documentReader.pdDocument, signatureOptions)
            //                if (pdSignatureField == null) { TODO find existing signature field?
            this.getVisibleSignatureFieldBoxPosition(signatureDrawer, documentReader, imageParameters.fieldParameters)
            //                }
            signatureDrawer.draw()
            documentReader.pdDocument.addSignature(signature, signatureInterface, signatureOptions)
        } else {
            documentReader.pdDocument.addSignature(signature, signatureInterface)
        }
        val externalSigning = documentReader.pdDocument.saveIncrementalForExternalSigning(baos)
        // invoke external signature service
        externalSigning.setSignature(signatureContent)
        logger.info("End signing {}", signatureLog)
        return digest.digest()
    }

    private fun loadSignatureDrawer(imageParameters: SignatureImageParameters?): SignatureDrawer {
        val signatureDrawer: SignatureDrawer = this.signatureDrawerFactory.getSignatureDrawer(imageParameters)
        return signatureDrawer
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
        if (PdfModificationDetectionUtils.isAnnotationBoxOverlapping(signatureFieldBox, pdfAnnotations)) {
            this.alertOnSignatureFieldOverlap()
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
}
