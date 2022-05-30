package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.IPrivateKeyEntry
import com.sphereon.vdx.ades.sign.util.CertificateUtil
import com.sphereon.vdx.ades.sign.util.toJavaPrivateKey
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm
import eu.europa.esig.dss.model.DSSException
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.token.DSSPrivateKeyEntry
import java.security.PrivateKey

class DSSWrappedKeyEntry(keyEntry: IKeyEntry) : DSSPrivateKeyEntry {

    /** The key's alias  */
    private val alias: String = keyEntry.alias

    /** The certificate  */
    private val certificate: CertificateToken?

    /** The corresponding certificate chain  */
    private val certificateChain: Array<CertificateToken>?

    /** The private key  */
    private var privateKey: PrivateKey?

    init {
        certificate = if (keyEntry.certificate != null)
            CertificateToken(CertificateUtil.toX509Certificate(keyEntry.certificate!!)) else null

        certificateChain = if (keyEntry.certificateChain != null)
            keyEntry.certificateChain!!.map { CertificateToken(CertificateUtil.toX509Certificate(it)) }.toTypedArray() else null

        privateKey = if (keyEntry is IPrivateKeyEntry) keyEntry.privateKey.toJavaPrivateKey() else null
    }

    /**
     * Get the entry alias
     *
     * @return the alias
     */
    fun getAlias(): String {
        return alias
    }

    override fun getCertificate(): CertificateToken? {
        return certificate
    }

    override fun getCertificateChain(): Array<CertificateToken>? {
        return certificateChain
    }

    /**
     * Get the private key
     *
     * @return the private key
     */
    fun getPrivateKey(): PrivateKey? {
        return privateKey
    }

    @Throws(DSSException::class)
    override fun getEncryptionAlgorithm(): EncryptionAlgorithm? {
        return EncryptionAlgorithm.forKey(certificate!!.publicKey)
    }

}
