package com.sphereon.vdx.ades.sign.util

import com.sphereon.vdx.ades.enums.SignatureForm
import com.sphereon.vdx.ades.model.SignatureConfiguration
import com.sphereon.vdx.pkcs7.PKCS7Service
import eu.europa.esig.dss.AbstractSignatureParameters
import eu.europa.esig.dss.cades.signature.CAdESService
import eu.europa.esig.dss.jades.signature.JAdESService
import eu.europa.esig.dss.model.TimestampParameters
import eu.europa.esig.dss.pades.signature.PAdESService
import eu.europa.esig.dss.signature.AbstractSignatureService
import eu.europa.esig.dss.validation.CommonCertificateVerifier

class AdESServiceFactory {
    companion object {
        fun getService(signatureForm: SignatureForm?): AbstractSignatureService<out AbstractSignatureParameters<out TimestampParameters>, out TimestampParameters> {
            if (signatureForm == null) {
                throw RuntimeException("Please provide a signature form to get an AdES Service!")
            }
            val certificateVerifier = CommonCertificateVerifier()
            return when (signatureForm) {
                SignatureForm.CAdES -> CAdESService(certificateVerifier)
                SignatureForm.PAdES -> PAdESService(certificateVerifier)
                SignatureForm.JAdES -> JAdESService(certificateVerifier)
                SignatureForm.PKCS7 -> PKCS7Service(certificateVerifier)
                else -> throw RuntimeException("Cannot create service for signature form " + signatureForm.name)
            }

        }
/*
        fun getService(signatureLevel: SignatureLevel?): AbstractSignatureService<out AbstractSignatureParameters<out TimestampParameters>, out TimestampParameters> {
            return getService(signatureLevel?.form)
        }*/

        fun getService(signatureConfiguration: SignatureConfiguration): AbstractSignatureService<out AbstractSignatureParameters<out TimestampParameters>, out TimestampParameters> {
            return getService(signatureConfiguration.signatureParameters.signatureForm())
        }

    }
}
