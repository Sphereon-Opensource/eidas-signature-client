package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.SigningException
import com.sphereon.vdx.ades.enums.DigestAlg
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.model.CertificateProviderSettings
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.SignInput
import com.sphereon.vdx.ades.model.Signature
import com.sphereon.vdx.ades.sign.util.*
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection
import eu.europa.esig.dss.token.KSPrivateKeyEntry


class LocalCertificateProviderService(settings: CertificateProviderSettings) : AbstractCertificateProviderService(settings) {

    // TODO: Create provider so we can move this to the abstract class and even move createSignatureImpl there
    private val tokenConnection = ConnectionFactory.connection(settings)


    override fun getKeys(): List<IKeyEntry> {
        return tokenConnection.keys.map { if (it is KSPrivateKeyEntry) it.fromDSS(it.alias) else it.fromDSS(it.certificate.toCertificate().fingerPrint) }
    }

    override fun getKey(alias: String): IKeyEntry? {
        return cacheService.get(alias) ?: when (tokenConnection) {
            is AbstractKeyStoreTokenConnection -> {
                val key = tokenConnection.getKey(alias)?.fromDSS(alias)
                if (key != null) {
                    cacheService.put(key)
                }
                return key
            }
            else -> getKeys().first { it.alias == alias }
        }
    }

    override fun createSignatureImpl(signInput: SignInput, keyEntry: IKeyEntry, mgf: MaskGenFunction?): Signature {
        if (signInput.digestAlgorithm == null) throw SigningException("Digest algorithm needs to be specified at this point")

        return if (signInput.signMode == SignMode.DIGEST && signInput.digestAlgorithm != DigestAlg.NONE) {
            tokenConnection.signDigest(signInput.toDigest(), mgf?.toDSS(), keyEntry.toDSS()).fromDSS(signMode = signInput.signMode, keyEntry)
        } else {
            tokenConnection.sign(signInput.toBeSigned(), signInput.digestAlgorithm.toDSS(), mgf?.toDSS(), keyEntry.toDSS())
                .fromDSS(signMode = signInput.signMode, keyEntry)
        }
    }
}
