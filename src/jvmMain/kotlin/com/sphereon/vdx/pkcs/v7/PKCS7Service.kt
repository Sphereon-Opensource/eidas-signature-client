package com.sphereon.vdx.pkcs.v7

import eu.europa.esig.dss.AbstractSignatureParameters
import eu.europa.esig.dss.model.DSSDocument
import eu.europa.esig.dss.model.SignatureValue
import eu.europa.esig.dss.model.TimestampParameters
import eu.europa.esig.dss.model.ToBeSigned
import eu.europa.esig.dss.signature.AbstractSignatureService
import eu.europa.esig.dss.validation.CertificateVerifier
import eu.europa.esig.dss.validation.timestamp.TimestampToken

class PKCS7Service(certificateVerifier: CertificateVerifier?) : AbstractSignatureService<AbstractSignatureParameters<out TimestampParameters>, TimestampParameters>(
    certificateVerifier
) {
    override fun getDataToSign(p0: DSSDocument?, p1: AbstractSignatureParameters<out TimestampParameters>?): ToBeSigned {
        TODO("Not yet implemented")
    }

    override fun signDocument(p0: DSSDocument?, p1: AbstractSignatureParameters<out TimestampParameters>?, p2: SignatureValue?): DSSDocument {
        TODO("Not yet implemented")
    }

    override fun extendDocument(p0: DSSDocument?, p1: AbstractSignatureParameters<out TimestampParameters>?): DSSDocument {
        TODO("Not yet implemented")
    }

    override fun getContentTimestamp(p0: DSSDocument?, p1: AbstractSignatureParameters<out TimestampParameters>?): TimestampToken {
        TODO("Not yet implemented")
    }
}