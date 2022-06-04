/*
 * Copyright 2017 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.sphereon.vdx.pkcs7.support

import org.apache.commons.logging.LogFactory
import org.apache.pdfbox.cos.COSArray
import org.apache.pdfbox.cos.COSDictionary
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.encryption.SecurityProvider
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.bouncycastle.asn1.ASN1Object
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.tsp.TSPException
import org.bouncycastle.tsp.TimeStampToken
import org.bouncycastle.util.Selector
import java.io.IOException
import java.security.cert.CertificateException
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate

/**
 * Utility class for the signature / timestamp examples.
 *
 * @author Tilman Hausherr
 */
object SigUtils {
    private val LOG = LogFactory.getLog(SigUtils::class.java)

    /**
     * Get the access permissions granted for this document in the DocMDP transform parameters dictionary. Details are described in the table "Entries
     * in the DocMDP transform parameters dictionary" in the PDF specification.
     *
     * @param doc document.
     * @return the permission value. 0 means no DocMDP transform parameters dictionary exists. Other return values are 1, 2 or 3. 2 is also returned
     * if the DocMDP transform parameters dictionary is found but did not contain a /P entry, or if the value is outside the valid range.
     */
    fun getMDPPermission(doc: PDDocument): Int {
        var base = doc.documentCatalog.cosObject.getDictionaryObject(COSName.PERMS)
        if (base is COSDictionary) {
            base = base.getDictionaryObject(COSName.DOCMDP)
            if (base is COSDictionary) {
                base = base.getDictionaryObject("Reference")
                if (base is COSArray) {
                    val refArray = base
                    for (i in 0 until refArray.size()) {
                        base = refArray.getObject(i)
                        if (base is COSDictionary) {
                            val sigRefDict = base
                            if (COSName.DOCMDP == sigRefDict.getDictionaryObject("TransformMethod")) {
                                base = sigRefDict.getDictionaryObject("TransformParams")
                                if (base is COSDictionary) {
                                    var accessPermissions = base.getInt(COSName.P, 2)
                                    if (accessPermissions < 1 || accessPermissions > 3) {
                                        accessPermissions = 2
                                    }
                                    return accessPermissions
                                }
                            }
                        }
                    }
                }
            }
        }
        return 0
    }

    /**
     * Set the access permissions granted for this document in the DocMDP transform parameters dictionary. Details are described in the table "Entries
     * in the DocMDP transform parameters dictionary" in the PDF specification.
     *
     * @param doc               The document.
     * @param signature         The signature object.
     * @param accessPermissions The permission value (1, 2 or 3).
     */
    fun setMDPPermission(doc: PDDocument, signature: PDSignature, accessPermissions: Int) {
        val sigDict = signature.cosObject

        // DocMDP specific stuff
        val transformParameters = COSDictionary()
        transformParameters.setItem(COSName.TYPE, COSName.getPDFName("TransformParams"))
        transformParameters.setInt(COSName.P, accessPermissions)
        transformParameters.setName(COSName.V, "1.2")
        transformParameters.isNeedToBeUpdated = true
        val referenceDict = COSDictionary()
        referenceDict.setItem(COSName.TYPE, COSName.getPDFName("SigRef"))
        referenceDict.setItem("TransformMethod", COSName.DOCMDP)
        referenceDict.setItem("DigestMethod", COSName.getPDFName("SHA1"))
        referenceDict.setItem("TransformParams", transformParameters)
        referenceDict.isNeedToBeUpdated = true
        val referenceArray = COSArray()
        referenceArray.add(referenceDict)
        sigDict.setItem("Reference", referenceArray)
        referenceArray.isNeedToBeUpdated = true

        // Catalog
        val catalogDict = doc.documentCatalog.cosObject
        val permsDict = COSDictionary()
        catalogDict.setItem(COSName.PERMS, permsDict)
        permsDict.setItem(COSName.DOCMDP, signature)
        catalogDict.isNeedToBeUpdated = true
        permsDict.isNeedToBeUpdated = true
    }

    /**
     * Log if the certificate is not valid for signature usage. Doing this anyway results in Adobe Reader failing to validate the PDF.
     *
     * @param x509Certificate
     * @throws CertificateParsingException
     */
    @Throws(CertificateParsingException::class)
    fun checkCertificateUsage(x509Certificate: X509Certificate) {
        // Check whether signer certificate is "valid for usage"
        // https://stackoverflow.com/a/52765021/535646
        // https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSig/changes.html#id1
        val keyUsage = x509Certificate.keyUsage
        if (keyUsage != null && !keyUsage[0] && !keyUsage[1]) {
            // (unclear what "signTransaction" is)
            // https://tools.ietf.org/html/rfc5280#section-4.2.1.3
            LOG.error(
                "Certificate key usage does not include " +
                        "digitalSignature nor nonRepudiation"
            )
        }
        val extendedKeyUsage = x509Certificate.extendedKeyUsage
        if (extendedKeyUsage != null &&
            !extendedKeyUsage.contains(KeyPurposeId.id_kp_emailProtection.toString()) &&
            !extendedKeyUsage.contains(KeyPurposeId.id_kp_codeSigning.toString()) &&
            !extendedKeyUsage.contains(KeyPurposeId.anyExtendedKeyUsage.toString()) &&
            !extendedKeyUsage.contains("1.2.840.113583.1.1.5") &&  // not mentioned in Adobe document, but tolerated in practice
            !extendedKeyUsage.contains("1.3.6.1.4.1.311.10.3.12")
        ) {
            LOG.error(
                "Certificate extended key usage does not include " +
                        "emailProtection, nor codeSigning, nor anyExtendedKeyUsage, " +
                        "nor 'Adobe Authentic Documents Trust'"
            )
        }
    }

    /**
     * Log if the certificate is not valid for timestamping.
     *
     * @param x509Certificate
     * @throws CertificateParsingException
     */
    @Throws(CertificateParsingException::class)
    fun checkTimeStampCertificateUsage(x509Certificate: X509Certificate) {
        val extendedKeyUsage = x509Certificate.extendedKeyUsage
        // https://tools.ietf.org/html/rfc5280#section-4.2.1.12
        if (extendedKeyUsage != null &&
            !extendedKeyUsage.contains(KeyPurposeId.id_kp_timeStamping.toString())
        ) {
            LOG.error("Certificate extended key usage does not include timeStamping")
        }
    }

    /**
     * Log if the certificate is not valid for responding.
     *
     * @param x509Certificate
     * @throws CertificateParsingException
     */
    @Throws(CertificateParsingException::class)
    fun checkResponderCertificateUsage(x509Certificate: X509Certificate) {
        val extendedKeyUsage = x509Certificate.extendedKeyUsage
        // https://tools.ietf.org/html/rfc5280#section-4.2.1.12
        if (extendedKeyUsage != null &&
            !extendedKeyUsage.contains(KeyPurposeId.id_kp_OCSPSigning.toString())
        ) {
            LOG.error("Certificate extended key usage does not include OCSP responding")
        }
    }

    /**
     * Gets the last relevant signature in the document, i.e. the one with the highest offset.
     *
     * @param document to get its last signature
     * @return last signature or null when none found
     */
    @Throws(IOException::class)
    fun getLastRelevantSignature(document: PDDocument): PDSignature? {
        val comparatorByOffset = Comparator.comparing { sig: PDSignature -> sig.byteRange[1] }

        // we can't use getLastSignatureDictionary() because this will fail (see PDFBOX-3978)
        // if a signature is assigned to a pre-defined empty signature field that isn't the last.
        // we get the last in time by looking at the offset in the PDF file.
        val optLastSignature = document.signatureDictionaries.stream().sorted(comparatorByOffset.reversed()).findFirst()
        if (optLastSignature.isPresent) {
            val lastSignature = optLastSignature.get()
            val type = lastSignature.cosObject.getItem(COSName.TYPE)
            if (COSName.SIG == type || COSName.DOC_TIME_STAMP == type) {
                return lastSignature
            }
        }
        return null
    }

    @Throws(CMSException::class, IOException::class, TSPException::class)
    fun extractTimeStampTokenFromSignerInformation(signerInformation: SignerInformation): TimeStampToken? {
        if (signerInformation.unsignedAttributes == null) {
            return null
        }
        val unsignedAttributes = signerInformation.unsignedAttributes
        // https://stackoverflow.com/questions/1647759/how-to-validate-if-a-signed-jar-contains-a-timestamp
        val attribute = unsignedAttributes[PKCSObjectIdentifiers.id_aa_signatureTimeStampToken] ?: return null
        val obj = attribute.attrValues.getObjectAt(0) as ASN1Object
        val signedTSTData = CMSSignedData(obj.encoded)
        return TimeStampToken(signedTSTData)
    }

    @Throws(TSPException::class, CertificateException::class, OperatorCreationException::class, IOException::class)
    fun validateTimestampToken(timeStampToken: TimeStampToken) {
        // https://stackoverflow.com/questions/42114742/
        val tstMatches// TimeStampToken.getSID() is untyped
                = timeStampToken.certificates.getMatches(timeStampToken.sid as Selector<X509CertificateHolder?>)
        val certificateHolder = tstMatches.iterator().next()
        val siv = JcaSimpleSignerInfoVerifierBuilder().setProvider(SecurityProvider.getProvider()).build(certificateHolder)
        timeStampToken.validate(siv)
    }
}