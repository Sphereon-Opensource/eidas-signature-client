package com.sphereon.vdx.pkcs7

import com.sphereon.vdx.pkcs7.support.SigUtils
import eu.europa.esig.dss.cades.CMSUtils
import eu.europa.esig.dss.cades.signature.CustomContentSigner
import eu.europa.esig.dss.enumerations.SignatureLevel
import eu.europa.esig.dss.enumerations.TimestampType
import eu.europa.esig.dss.model.*
import eu.europa.esig.dss.pdf.IPdfObjFactory
import eu.europa.esig.dss.pdf.PDFServiceMode
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxSignatureService
import eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer.PdfBoxNativeSignatureDrawerFactory
import eu.europa.esig.dss.signature.AbstractSignatureService
import eu.europa.esig.dss.signature.SigningOperation
import eu.europa.esig.dss.spi.DSSASN1Utils
import eu.europa.esig.dss.validation.CertificateVerifier
import eu.europa.esig.dss.validation.timestamp.TimestampToken
import mu.KotlinLogging
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.bouncycastle.cms.*
import org.bouncycastle.tsp.TSPException
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
        val messageDigest = computeDocumentDigest(toSignDocument, parameters)
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
/*
    override fun getDataToSign(toSignDocument: DSSDocument, parameters: PKCS7SignatureParameters): ToBeSigned {
        val dataToSign = PDDocument.load(toSignDocument.openStream()).use { document ->
            val accessPermissions = validateAndGetAccessPermissions(document)

            val outputStream = ByteArrayOutputStream()
            // create signature dictionary
            val signature = PDSignature()
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED)
            signature.name = parameters.signerName
            signature.location = parameters.location
            signature.reason = parameters.reason
            signature.contactInfo = parameters.contactInfo
            if (parameters.signatureMode == PdfSignatureMode.CERTIFICATION) {
                tryEnableCertification(accessPermissions, toSignDocument, document, signature)
            }
            // the signing date, needed for valid signature
            signature.signDate = Calendar.getInstance()
            document.addSignature(signature)
            document.saveIncrementalForExternalSigning(outputStream)
            outputStream.toByteArray()
        }
        return ToBeSigned(dataToSign)
    }*/

    private fun tryEnableCertification(
        accessPermissions: Int,
        dssDocument: DSSDocument,
        document: PDDocument,
        signature: PDSignature
    ) {
        // Optional: certify
        // can be done only if version is at least 1.5 and if not already set
        // doing this on a PDF/A-1b file fails validation by Adobe preflight (PDFBOX-3821)
        // PDF/A-1b requires PDF version 1.4 max, so don't increase the version on such files.
        // We create an approval signature when already certified before or at lower than 1.5 versions.
        if (accessPermissions != 0) {
            logger.warn(
                "Not certifying although mode was certify, because this is not the first signature for {}, {}", dssDocument.name
            )
        } else if (document.version < 1.5f) {
            logger.warn(
                "Not certifying although mode was certify, because document version {} for {}, {}", document.version, dssDocument.name
            )
        } else {
            SigUtils.setMDPPermission(document, signature, 2)
        }
    }

    private fun validateAndGetAccessPermissions(document: PDDocument): Int {
        val accessPermissions: Int = SigUtils.getMDPPermission(document)
        if (accessPermissions == 1) {
            throw UnsupportedOperationException(
                "No changes to the document are permitted due to DocMDP transform parameters dictionary"
            )
        }
        return accessPermissions
    }

    override fun signDocument(toSignDocument: DSSDocument, parameters: PKCS7SignatureParameters, signatureValue: SignatureValue): DSSDocument {
        assertSigningCertificateValid(parameters)
        val signatureValueChecked = ensureSignatureValue(parameters.signatureAlgorithm, signatureValue)
        val encodedData: ByteArray = generateSignedData(toSignDocument, parameters, signatureValueChecked)
        val pdfSignatureService = pdfObjFactory.newPAdESSignatureService()
        val pAdESSignatureParameters = parameters.toPAdESSignatureParameters()
        var signature = pdfSignatureService.sign(toSignDocument, encodedData, pAdESSignatureParameters)
        // TODO extendSignatures?
        parameters.reinit()
        signature.name = this.getFinalFileName(toSignDocument, SigningOperation.SIGN, SignatureLevel.CAdES_A)
            .replace("-cades-a", "")
            .plus(".pdf")
        return signature
    }

    private fun generateSignedData(
        toSignDocument: DSSDocument,
        parameters: PKCS7SignatureParameters,
        signatureValue: SignatureValue
    ): ByteArray {
        val signatureAlgorithm = parameters.signatureAlgorithm
        val signatureLevel = parameters.signatureLevel
        Objects.requireNonNull(signatureAlgorithm, "SignatureAlgorithm cannot be null!")
        Objects.requireNonNull(signatureLevel, "SignatureLevel must be defined!")
        val customContentSigner = CustomContentSigner(signatureAlgorithm.jceId, signatureValue.value)
        val messageDigest: ByteArray = this.computeDocumentDigest(toSignDocument, parameters)
        val signerInfoGeneratorBuilder: SignerInfoGeneratorBuilder =
            this.pkcs7CMSSignedDataBuilder.getSignerInfoGeneratorBuilder(parameters, messageDigest)
        val generator: CMSSignedDataGenerator = this.pkcs7CMSSignedDataBuilder.createCMSSignedDataGenerator(
            parameters,
            customContentSigner,
            signerInfoGeneratorBuilder,
            null as CMSSignedData?
        )
        val content = CMSProcessableByteArray(messageDigest)
        val data = CMSUtils.generateDetachedCMSSignedData(generator, content)
        return DSSASN1Utils.getDEREncoded(data)
    }

    private fun assertSignaturePossible(toSignDocument: DSSDocument) {
        require(toSignDocument !is DigestDocument) { "DigestDocument cannot be used for PDF-PKCS7!" }
    }


    override fun extendDocument(dssDocument: DSSDocument, parameters: PKCS7SignatureParameters): DSSDocument {
        throw java.lang.UnsupportedOperationException(String.format("Unsupported signature format '%s' for extension.", parameters.signatureLevel))
    }

    private fun computeDocumentDigest(toSignDocument: DSSDocument, parameters: PKCS7SignatureParameters): ByteArray {
        PdfBoxSignatureService(PDFServiceMode.SIGNATURE, PdfBoxNativeSignatureDrawerFactory())
        val pdfSignatureService = pdfObjFactory.newPAdESSignatureService()
        return pdfSignatureService.digest(toSignDocument, parameters.toPAdESSignatureParameters())
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
