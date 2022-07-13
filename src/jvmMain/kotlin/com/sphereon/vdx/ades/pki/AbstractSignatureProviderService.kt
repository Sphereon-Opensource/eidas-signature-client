package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.enums.SignatureAlg
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.sign.IKidSignatureService

abstract class AbstractSignatureProviderService() : IKidSignatureService {
//    override val keyProvider: IKeyProviderService
//        get() = KeyProviderSettings

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
        val key = keyProvider.getKey(kid)
        return keyProvider.createSignature(signInput, key!!) // TODO fix !!
    }

    override fun createSignature(signInput: SignInput, kid: String, mgf: MaskGenFunction): Signature {
        val key = keyProvider.getKey(kid)
        return keyProvider.createSignature(signInput, key!!, mgf) // TODO fix !!
    }

    override fun createSignature(signInput: SignInput, kid: String, signatureAlgorithm: SignatureAlg): Signature {
        val key = keyProvider.getKey(kid)
        return keyProvider.createSignature(signInput, key!!, signatureAlgorithm) // TODO fix !!
    }

    override fun isValidSignature(signInput: SignInput, signature: Signature, publicKey: Key): Boolean {
        return keyProvider.isValidSignature(signInput, signature, publicKey)
    }

    override fun isValidSignature(signInput: SignInput, signature: Signature, kid: String): Boolean {
        val key = keyProvider.getKey(kid)
        return keyProvider.isValidSignature(signInput, signature, key!!) // TODO fix !!
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
}
