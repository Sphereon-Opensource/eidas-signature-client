package com.sphereon.vdx.ades.sign

import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.enums.*
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.model.Key
import com.sphereon.vdx.ades.model.OrigData
import com.sphereon.vdx.ades.model.SignInput
import com.sphereon.vdx.ades.model.SignOutput
import com.sphereon.vdx.ades.model.Signature
import com.sphereon.vdx.ades.pki.IKeyProviderService
import com.sphereon.vdx.ades.rest.client.api.SigningApi
import com.sphereon.vdx.ades.rest.client.model.*
import com.sphereon.vdx.ades.sign.util.*

open class RestSignatureService(final override val keyProvider: IKeyProviderService, val restSigningClient: SigningApi) : IKidSignatureService {
    private val delegate = KeySignatureService(keyProvider)

    override fun digest(signInput: SignInput): SignInput {
        val digest = restSigningClient.digest(Digest()
            .signInput(signInput.toRestSignInput())
        )

        return digest.signInput.toLocalSignInput()
    }

    override fun createSignature(signInput: SignInput, kid: String): Signature {
        return delegate.createSignature(signInput, getKey(kid))
    }

    override fun createSignature(signInput: SignInput, kid: String, mgf: MaskGenFunction): Signature {
        return delegate.createSignature(signInput, getKey(kid), mgf)
    }

    override fun createSignature(signInput: SignInput, kid: String, signatureAlgorithm: SignatureAlg): Signature {
        return delegate.createSignature(signInput, getKey(kid), signatureAlgorithm)
    }

    override fun isValidSignature(signInput: SignInput, signature: Signature, kid: String): Boolean {
        return delegate.isValidSignature(signInput, signature, getKey(kid))
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
        val signInputResponse = restSigningClient.determineSignInput(
            DetermineSignInput()
                .origData(origData.toRestOrigData())
                .signMode(com.sphereon.vdx.ades.rest.client.model.SignMode.valueOf(signMode.name))
                .binding(com.sphereon.vdx.ades.rest.client.model.ConfigKeyBinding()
                    .kid(kid)
                    .keyProviderId(keyProvider.settings.id)
                )
        )

        return signInputResponse.signInput.toLocalSignInput()
    }

    override fun sign(origData: OrigData, kid: String, signMode: SignMode, signatureConfiguration: SignatureConfiguration): SignOutput {
        val signInput = determineSignInput(origData, kid, signMode, signatureConfiguration)
        val signature = createSignature(signInput, kid)

        return sign(origData, signature, signatureConfiguration)
    }

    override fun sign(origData: OrigData, signature: Signature, signatureConfiguration: SignatureConfiguration): SignOutput {
        val mergeSignatureResponse = restSigningClient.mergeSignature(MergeSignature()
            .origData(origData.toRestOrigData())
            .signature(signature.toRestSignature())
        )

        return mergeSignatureResponse.signOutput.toLocalSignOutput()
    }

    private fun getKey(kid: String): IKeyEntry {
        return keyProvider.getKey(kid) ?: throw PKIException("Could not retrieve key entry for kid $kid")
    }

}
