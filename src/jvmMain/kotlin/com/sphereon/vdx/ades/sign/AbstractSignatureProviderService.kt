package com.sphereon.vdx.ades.sign

import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.enums.SignatureAlg
import com.sphereon.vdx.ades.model.*

abstract class AbstractSignatureProviderService() : IKidSignatureService {
    override fun determineSignInput(
        origData: OrigData,
        kid: String,
        signMode: SignMode,
        signatureConfiguration: SignatureConfiguration
    ): SignInput {
        return determineSignInputImpl(origData, kid, signMode, signatureConfiguration)
    }

    override fun digest(signInput: SignInput): SignInput {
        return digestImpl(signInput)
    }

    override fun createSignature(signInput: SignInput, kid: String): Signature {
        return keyProvider.createSignature(signInput, getKey(kid))
    }

    override fun createSignature(signInput: SignInput, kid: String, mgf: MaskGenFunction): Signature {
        return keyProvider.createSignature(signInput, getKey(kid), mgf)
    }

    override fun createSignature(signInput: SignInput, kid: String, signatureAlgorithm: SignatureAlg): Signature {
        return keyProvider.createSignature(signInput, getKey(kid), signatureAlgorithm)
    }

    override fun isValidSignature(signInput: SignInput, signature: Signature, publicKey: Key): Boolean {
        return keyProvider.isValidSignature(signInput, signature, publicKey)
    }

    override fun isValidSignature(signInput: SignInput, signature: Signature, kid: String): Boolean {
        return keyProvider.isValidSignature(signInput, signature, getKey(kid))
    }

    override fun sign(
        origData: OrigData,
        kid: String,
        signMode: SignMode,
        signatureConfiguration: SignatureConfiguration
    ): SignOutput {
        return signImpl(origData, kid, signMode, signatureConfiguration)
    }

    override fun sign(
        origData: OrigData,
        signature: Signature,
        signatureConfiguration: SignatureConfiguration
    ): SignOutput {
        return signImpl(origData, signature, signatureConfiguration)
    }

    protected abstract fun determineSignInputImpl(origData: OrigData, kid: String, signMode: SignMode, signatureConfiguration: SignatureConfiguration): SignInput

    protected abstract fun digestImpl(signInput: SignInput): SignInput

    protected abstract fun signImpl(origData: OrigData, kid: String, signMode: SignMode, signatureConfiguration: SignatureConfiguration): SignOutput

    protected abstract fun signImpl(origData: OrigData, signature: Signature, signatureConfiguration: SignatureConfiguration): SignOutput

    private fun getKey(kid: String): IKeyEntry {
        return keyProvider.getKey(kid) ?: throw PKIException("Could not retrieve key entry for kid $kid")
    }
}
