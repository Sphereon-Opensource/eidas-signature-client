package com.sphereon.vdx.pkcs7

import eu.europa.esig.dss.cades.CAdESSignatureParameters
import eu.europa.esig.dss.cades.signature.CAdESLevelBaselineB
import eu.europa.esig.dss.cades.signature.CMSSignedDataBuilder
import eu.europa.esig.dss.model.DSSException
import eu.europa.esig.dss.validation.CertificateVerifier
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.SignerInfoGeneratorBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.DigestCalculatorProvider
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider

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

    fun getSignerInfoGeneratorBuilder(parameters: PKCS7SignatureParameters, messageDigest: ByteArray): SignerInfoGeneratorBuilder {
        val cadesLevelBaselineB = CAdESLevelBaselineB(true)
        val pkcS7Baseline = PKCS7Baseline()
        val digestCalculatorProvider: DigestCalculatorProvider = BcDigestCalculatorProvider()
        var signerInfoGeneratorBuilder = SignerInfoGeneratorBuilder(digestCalculatorProvider)
        signerInfoGeneratorBuilder = signerInfoGeneratorBuilder.setSignedAttributeGenerator { params ->
            pkcS7Baseline.getSignedAttributes(
                params,
                cadesLevelBaselineB,
                parameters,
                messageDigest
            )
        }
        signerInfoGeneratorBuilder = signerInfoGeneratorBuilder.setUnsignedAttributeGenerator { pkcS7Baseline.unsignedAttributes }
        return signerInfoGeneratorBuilder
    }
}