package com.sphereon.vdx.ades.sign.util

import com.sphereon.vdx.ades.SigningException
import com.sphereon.vdx.ades.enums.SignatureForm
import com.sphereon.vdx.ades.model.Certificate
import com.sphereon.vdx.ades.model.SignatureConfiguration
import com.sphereon.vdx.pkcs7.PKCS7Service
import eu.europa.esig.dss.AbstractSignatureParameters
import eu.europa.esig.dss.alert.LogOnStatusAlert
import eu.europa.esig.dss.cades.signature.CAdESService
import eu.europa.esig.dss.jades.signature.JAdESService
import eu.europa.esig.dss.model.TimestampParameters
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.pades.signature.PAdESService
import eu.europa.esig.dss.service.crl.OnlineCRLSource
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource
import eu.europa.esig.dss.signature.AbstractSignatureService
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource
import eu.europa.esig.dss.validation.CommonCertificateVerifier


class AdESServiceFactory {
    companion object {
        fun getService(
            signatureForm: SignatureForm?,
            certificateChain: List<Certificate>?
        ): AbstractSignatureService<out AbstractSignatureParameters<out TimestampParameters>, out TimestampParameters> {
            if (signatureForm == null) {
                throw SigningException("Please provide a signature form to get an AdES Service!")
            }
            val certificateVerifier = CommonCertificateVerifier()
            certificateVerifier.isCheckRevocationForUntrustedChains = true

            // We can inject several sources. eg: OCSP, CRL, AIA, trusted lists

            // Capability to download resources from AIA
            // We can inject several sources. eg: OCSP, CRL, AIA, trusted lists

            // Capability to download resources from AIA
            certificateVerifier.aiaSource = DefaultAIASource()

            // Capability to request OCSP Responders
            certificateVerifier.ocspSource = OnlineOCSPSource()

            // Capability to download CRL
            certificateVerifier.crlSource = OnlineCRLSource()

            certificateVerifier.alertOnMissingRevocationData = LogOnStatusAlert()



            if (certificateChain != null) {

                // Create an instance of a trusted certificate source
                val trustedCertSource = CommonTrustedCertificateSource()

                // import the keystore as trusted

                certificateChain.map { trustedCertSource.addCertificate(CertificateToken(it.toX509Certificate())) }
                certificateVerifier.addTrustedCertSources(trustedCertSource)
            }

            return when (signatureForm) {
                SignatureForm.CAdES -> CAdESService(certificateVerifier)
                SignatureForm.PAdES -> PAdESService(certificateVerifier)
                SignatureForm.JAdES -> JAdESService(certificateVerifier)
                SignatureForm.PKCS7 -> PKCS7Service(certificateVerifier)
                else -> throw SigningException("Cannot create service for signature form " + signatureForm.name)
            }

        }
/*
        fun getService(signatureLevel: SignatureLevel?): AbstractSignatureService<out AbstractSignatureParameters<out TimestampParameters>, out TimestampParameters> {
            return getService(signatureLevel?.form)
        }*/

        fun getService(signatureConfiguration: SignatureConfiguration): AbstractSignatureService<out AbstractSignatureParameters<out TimestampParameters>, out TimestampParameters> {
            return getService(signatureConfiguration.signatureParameters.signatureForm(), signatureConfiguration.signatureParameters.certificateChain)
        }

    }
}
