package com.sphereon.vdx.ades.sign

import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.enums.SignatureAlg
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.pki.IKeyProviderService


open class KidSignatureService(final override val keyProvider: IKeyProviderService) : IKidSignatureService {

    private val delegate = KeySignatureService(keyProvider)

    override fun digest(signInput: SignInput): SignInput {
        return delegate.digest(signInput)
    }

    override fun createSignature(signInput: SignInput): Signature {
        return delegate.createSignature(signInput, getKey(signInput.binding.kid))
    }

    override fun createSignature(signInput: SignInput, mgf: MaskGenFunction): Signature {
        return delegate.createSignature(signInput, getKey(signInput.binding.kid), mgf)
    }

    override fun createSignature(signInput: SignInput, signatureAlgorithm: SignatureAlg): Signature {
        return delegate.createSignature(signInput, getKey(signInput.binding.kid), signatureAlgorithm)
    }

    override fun isValidSignature(signInput: SignInput, signature: Signature): Boolean {
        return delegate.isValidSignature(signInput, signature, getKey(signInput.binding.kid))
    }


    override fun isValidSignature(signInput: SignInput, signature: Signature, publicKey: Key): Boolean {
        return delegate.isValidSignature(signInput, signature, publicKey)
    }


    override fun determineSignInput(
        origData: OrigData,
        kid: String,
        signMode: SignMode,
        signatureConfiguration: SignatureConfiguration
    ): SignInput {
        return delegate.determineSignInput(origData, getKey(kid), signMode, signatureConfiguration)
    }

    override fun sign(origData: OrigData, kid: String, signMode: SignMode, signatureConfiguration: SignatureConfiguration): SignOutput {
        return delegate.sign(origData, getKey(kid), signMode, signatureConfiguration)
    }

    override fun sign(origData: OrigData, signature: Signature, signatureConfiguration: SignatureConfiguration): SignOutput {
        return delegate.sign(origData, signature, signatureConfiguration)
    }

    private fun getKey(kid: String): IKeyEntry {
        return keyProvider.getKey(kid) ?: throw PKIException("Could not retrieve key entry for kid $kid")
    }

}
