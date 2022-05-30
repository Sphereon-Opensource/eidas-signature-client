package com.sphereon.vdx.ades.sign

import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.enums.SignatureAlg
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.pki.ICertificateProviderService


open class AliasSignatureService(override val certificateProvider: ICertificateProviderService) : IAliasSignatureService {

    private val delegate = KeySignatureService(certificateProvider)

    override fun digest(signInput: SignInput): SignInput {
        return delegate.digest(signInput)
    }

    override fun createSignature(signInput: SignInput, certificateAlias: String): Signature {
        return delegate.createSignature(signInput, getKey(certificateAlias))
    }

    override fun createSignature(signInput: SignInput, certificateAlias: String, mgf: MaskGenFunction): Signature {
        return delegate.createSignature(signInput, getKey(certificateAlias), mgf)
    }

    override fun createSignature(signInput: SignInput, certificateAlias: String, signatureAlgorithm: SignatureAlg): Signature {
        return delegate.createSignature(signInput, getKey(certificateAlias), signatureAlgorithm)
    }

    override fun isValidSignature(signInput: SignInput, signature: Signature, publicKeyAlias: String): Boolean {
        return delegate.isValidSignature(signInput, signature, getKey(publicKeyAlias))
    }


    override fun isValidSignature(signInput: SignInput, signature: Signature, publicKey: Key): Boolean {
        return delegate.isValidSignature(signInput, signature, publicKey)
    }


    override fun determineSignInput(
        origData: OrigData,
        alias: String,
        signMode: SignMode,
        signatureConfiguration: SignatureConfiguration
    ): SignInput {
        return delegate.determineSignInput(origData, getKey(alias), signMode, signatureConfiguration)
    }

    override fun sign(origData: OrigData, certificateAlias: String, signMode: SignMode, signatureConfiguration: SignatureConfiguration): SignOutput {
        return delegate.sign(origData, getKey(certificateAlias), signMode, signatureConfiguration)
    }

    override fun sign(origData: OrigData, signature: Signature, signatureConfiguration: SignatureConfiguration): SignOutput {
        return delegate.sign(origData, signature, signatureConfiguration)
    }

    private fun getKey(alias: String): IKeyEntry {
        return certificateProvider.getKey(alias) ?: throw PKIException("Could not retrieve key entry for alias $alias")
    }

}
