package com.sphereon.vdx.ades.sign.util

import com.sphereon.vdx.ades.model.Certificate
import kotlinx.datetime.toKotlinInstant
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.xml.bind.DatatypeConverter

object CertificateUtil {

    fun toX509Certificate(certificate: Certificate): X509Certificate {
        val certFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
        return certFactory.generateCertificate(ByteArrayInputStream(certificate.value)) as X509Certificate
    }

    fun toCertificate(certificate: X509Certificate): Certificate {
        return Certificate(
            value = certificate.encoded,
            fingerPrint = fingerPrint(certificate),
            serialNumber = certificate.serialNumber.longValueExact(),
            issuerDN = certificate.issuerDN.toString(),
            subjectDN = certificate.subjectDN.toString(),
            notBefore = certificate.notBefore.toInstant().toKotlinInstant(),
            notAfter = certificate.notAfter.toInstant().toKotlinInstant(),
            keyUsage = keyUsage(certificate.keyUsage)
        )

    }

    fun keyUsage(input: BooleanArray?): Map<String, Boolean>? {
        if (input == null) {
            return null
        }
        val result = mutableMapOf<String, Boolean>()
        result["digitalSignature"] = input[0]
        result["nonRepudiation"] = input[1]
        result["keyEncipherment"] = input[2]
        result["dataEncipherment"] = input[3]
        result["keyAgreement"] = input[4]
        result["keyCertSign"] = input[5]
        result["cRLSign"] = input[6]
        result["encipherOnly"] = input[7]
        result["decipherOnly"] = input[8]
        return result
    }

    fun fingerPrint(x509Certificate: X509Certificate): String {
        val md = MessageDigest.getInstance("SHA-1")
        return DatatypeConverter.printHexBinary(md.digest(x509Certificate.encoded))
    }

    fun fingerPrint(certificate: Certificate): String {
        val md = MessageDigest.getInstance("SHA-1")
        return DatatypeConverter.printHexBinary(md.digest(certificate.value))
    }
}
