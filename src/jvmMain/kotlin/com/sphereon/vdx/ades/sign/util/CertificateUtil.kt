package com.sphereon.vdx.ades.sign.util

import com.sphereon.vdx.ades.enums.CryptoAlg
import com.sphereon.vdx.ades.model.Certificate
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.KeyEntry
import jakarta.xml.bind.DatatypeConverter
import kotlinx.datetime.toKotlinInstant
import mu.KotlinLogging
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers
import org.jose4j.base64url.Base64
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.cert.X509Extension


object CertificateUtil {

    private val logger = KotlinLogging.logger {}

    fun toX509Certificate(certificate: Certificate): X509Certificate {
        val certFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
        return certFactory.generateCertificate(ByteArrayInputStream(certificate.value)) as X509Certificate
    }

    fun toX509Certificate(certificateBase64: String): X509Certificate {
        return toX509Certificate(Base64.decode(certificateBase64))
    }

    fun toX509Certificate(certificate: ByteArray): X509Certificate {
        val certFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
        return certFactory.generateCertificate(ByteArrayInputStream(certificate)) as X509Certificate
    }

    fun toCertificate(certificate: X509Certificate): Certificate {
        return Certificate(
            value = certificate.encoded,
            fingerPrint = fingerPrint(certificate),
            serialNumber = certificate.serialNumber.toString(),
            issuerDN = certificate.issuerDN.toString(),
            subjectDN = certificate.subjectDN.toString(),
            notBefore = certificate.notBefore.toInstant().toKotlinInstant(),
            notAfter = certificate.notAfter.toInstant().toKotlinInstant(),
            keyUsage = keyUsage(certificate.keyUsage)
        )

    }


    fun toKeyEntry(x509Certificate: X509Certificate, kid: String): IKeyEntry {
        val certificate = toCertificate(x509Certificate)
        return KeyEntry(
            kid = kid,
            publicKey = x509Certificate.toPublicKey(),
            certificate = certificate,
            encryptionAlgorithm = CryptoAlg.valueOf(x509Certificate.sigAlgName)
            // TODO: certChain
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

    fun keyUsage(input: List<String>?): Map<String, Boolean>? {
        if (input == null) {
            return null
        }
        val result = mutableMapOf<String, Boolean>()
        result["digitalSignature"] = false
        result["nonRepudiation"] = false
        result["keyEncipherment"] = false
        result["dataEncipherment"] = false
        result["keyAgreement"] = false
        result["keyCertSign"] = false
        result["cRLSign"] = false
        result["encipherOnly"] = false
        result["decipherOnly"] = false
        input.forEach { result[it] = true }
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


    /**
     * Download extra certificates from the URI mentioned in id-ad-caIssuers in the "authority
     * information access" extension. The method is lenient, i.e. catches all exceptions.
     *
     * @param x509Extension an X509 object that can have extensions.
     *
     * @return a certificate set, never null.
     */
    fun downloadExtraCertificates(x509Extension: X509Extension, recursive: Boolean? = true): List<X509Certificate> {
        // https://tools.ietf.org/html/rfc2459#section-4.2.2.1
        // https://tools.ietf.org/html/rfc3280#section-4.2.2.1
        // https://tools.ietf.org/html/rfc4325
        val downloadedCerts: MutableList<X509Certificate> = ArrayList()
        val authorityExtensionValue =
            x509Extension.getExtensionValue(org.bouncycastle.asn1.x509.Extension.authorityInfoAccess.id) ?: return downloadedCerts
        val asn1Prim: org.bouncycastle.asn1.ASN1Primitive = try {
            org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils.parseExtensionValue(authorityExtensionValue)
        } catch (ex: IOException) {
            logger.warn(ex.message, ex)
            return downloadedCerts
        }
        if (asn1Prim !is ASN1Sequence) {
            logger.warn("ASN1Sequence expected, got " + asn1Prim.javaClass.simpleName)
            return downloadedCerts
        }
        val asn1Seq = asn1Prim
        val objects = asn1Seq.objects
        while (objects.hasMoreElements()) {
            // AccessDescription
            val obj = objects.nextElement() as ASN1Sequence
            val oid = obj.getObjectAt(0)
            if (!X509ObjectIdentifiers.id_ad.equals(oid) && !X509ObjectIdentifiers.id_ad_caIssuers.equals(oid)) {
                continue
            }
            val location = obj.getObjectAt(1) as ASN1TaggedObject
            val uri = location.getObject() as ASN1OctetString
            // TODO: Add cache, getting all the CAs over and over is expensive
            val urlString = String(uri.octets)
            var `in`: java.io.InputStream? = null
            try {
                logger.info("CA issuers URL: $urlString")
                `in` = java.net.URL(urlString).openStream()
                val certFactory = CertificateFactory.getInstance("X.509")
                val altCerts = certFactory.generateCertificates(`in`)
                for (altCert in altCerts) {
                    if (altCert is X509Certificate) {
                        if (downloadedCerts.contains(altCert)) {
                            continue
                        }
                        logger.info("x509 subjectDN: ${altCert.subjectDN}")

                        downloadedCerts.add(altCert)
                        if (recursive == true) {
                            downloadedCerts.addAll(downloadExtraCertificates(altCert, recursive))
                        }
                    }
                }
                logger.info("CA issuers URL: ${altCerts.size} certificate(s) downloaded")
            } catch (ex: IOException) {
                logger.warn(urlString + " failure: ${ex.message}", ex)
            } catch (ex: java.security.cert.CertificateException) {
                logger.warn(ex.message, ex)
            } finally {
                org.apache.pdfbox.io.IOUtils.closeQuietly(`in`)
            }
        }
        logger.info("CA issuers: Downloaded ${downloadedCerts.size} certificate(s) total")
        return downloadedCerts
    }
}
