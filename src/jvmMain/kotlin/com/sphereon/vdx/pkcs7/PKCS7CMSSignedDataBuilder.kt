package com.sphereon.vdx.pkcs7

import eu.europa.esig.dss.cades.CAdESSignatureParameters
import eu.europa.esig.dss.cades.signature.CMSSignedDataBuilder
import eu.europa.esig.dss.model.DSSException
import eu.europa.esig.dss.validation.CertificateVerifier
import org.apache.pdfbox.io.IOUtils
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator
import org.bouncycastle.cms.SignerInfoGeneratorBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider
import java.io.InputStream
import java.security.MessageDigest

class PKCS7CMSSignedDataBuilder(certificateVerifier: CertificateVerifier?) : CMSSignedDataBuilder(certificateVerifier) {
    @Throws(DSSException::class)

    public override fun createCMSSignedDataGenerator(
        parameters: CAdESSignatureParameters,
        contentSigner: ContentSigner,
        signerInfoGeneratorBuilder: SignerInfoGeneratorBuilder,
        originalSignedData: CMSSignedData?
    ): CMSSignedDataGenerator {
        return super.createCMSSignedDataGenerator(parameters, contentSigner, signerInfoGeneratorBuilder, originalSignedData)
    }

    fun getSignerInfoGeneratorBuilder(parameters: PKCS7SignatureParameters, content: InputStream): SignerInfoGeneratorBuilder {
        val digestAlgorithm = parameters.contentTimestampParameters.digestAlgorithm
        val messageDigest = MessageDigest.getInstance(digestAlgorithm.name)
        messageDigest.update(IOUtils.toByteArray(content))

        val attr = Attribute(CMSAttributes.messageDigest, DERSet(DEROctetString(messageDigest.digest())))
        val vector = ASN1EncodableVector()
        vector.add(attr)

        return SignerInfoGeneratorBuilder(BcDigestCalculatorProvider())
            .setSignedAttributeGenerator(DefaultSignedAttributeTableGenerator(AttributeTable(vector)));
    }
}
