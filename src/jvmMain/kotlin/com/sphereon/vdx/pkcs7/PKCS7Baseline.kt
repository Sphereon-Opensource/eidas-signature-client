package com.sphereon.vdx.pkcs7

import eu.europa.esig.dss.cades.signature.CAdESLevelBaselineB
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.asn1.cms.CMSAttributes

internal class PKCS7Baseline {
    // TODO fix / compare to PDFStamper 
    fun getSignedAttributes(
        params: Map<*, *>,
        cadesProfile: CAdESLevelBaselineB,
        parameters: PKCS7SignatureParameters?,
        messageDigest: ByteArray?
    ): AttributeTable {
        var signedAttributes = cadesProfile.getSignedAttributes(parameters)
        if (signedAttributes[CMSAttributes.contentType] == null) {
            val contentType = params["contentType"] as ASN1ObjectIdentifier?
            if (contentType != null) {
                signedAttributes = signedAttributes.add(CMSAttributes.contentType, contentType)
            }
        }
        if (signedAttributes[CMSAttributes.messageDigest] == null) {
            signedAttributes = signedAttributes.add(CMSAttributes.messageDigest, DEROctetString(messageDigest))
        }
        return signedAttributes
    }

    val unsignedAttributes: AttributeTable?
        get() = null
}