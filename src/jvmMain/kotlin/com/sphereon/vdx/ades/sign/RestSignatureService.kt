package com.sphereon.vdx.ades.sign

import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.enums.*
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.model.ConfigKeyBinding
import com.sphereon.vdx.ades.model.Key
import com.sphereon.vdx.ades.model.OrigData
import com.sphereon.vdx.ades.model.SignInput
import com.sphereon.vdx.ades.model.SignOutput
import com.sphereon.vdx.ades.model.Signature
import com.sphereon.vdx.ades.pki.IKeyProviderService
import com.sphereon.vdx.ades.rest.client.api.SigningApi
import com.sphereon.vdx.ades.rest.client.model.*
import com.sphereon.vdx.ades.rest.client.model.KeyEntry
import kotlinx.datetime.Instant

open class RestSignatureService(final override val keyProvider: IKeyProviderService, val restSigningClient: SigningApi) : IKidSignatureService {

    private val delegate = KeySignatureService(keyProvider)

    override fun digest(signInput: SignInput): SignInput {
        val digest = restSigningClient.digest(
            Digest().signInput(
                com.sphereon.vdx.ades.rest.client.model.SignInput()
                    .name(signInput.name)
                    .input(signInput.input)
                    .signMode(com.sphereon.vdx.ades.rest.client.model.SignMode.valueOf(signInput.signMode.name))
                    .digestAlgorithm(signInput.digestAlgorithm?.name?.let { DigestAlgorithm.valueOf(it) })
                    .signingDate(java.time.Instant.ofEpochSecond(signInput.signingDate.epochSeconds))
                    .binding(
                        com.sphereon.vdx.ades.rest.client.model.ConfigKeyBinding()
                        .kid(signInput.binding.kid)
                        .signatureConfigId(signInput.binding.signatureConfigId)
                        .keyProviderId(signInput.binding.keyProviderId)
                    )
            )
        )

        return signInputFrom(digest.signInput)
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
            .origData(com.sphereon.vdx.ades.rest.client.model.OrigData()
                .name(origData.name)
                .content(origData.value)
                .mimeType(origData.mimeType))
            .signMode(com.sphereon.vdx.ades.rest.client.model.SignMode.valueOf(signMode.name))
            .binding(
                com.sphereon.vdx.ades.rest.client.model.ConfigKeyBinding()
                    .kid(kid)
                    .keyProviderId(keyProvider.settings.id)
            ))

        return signInputFrom(signInputResponse.signInput)
    }

    override fun sign(origData: OrigData, kid: String, signMode: SignMode, signatureConfiguration: SignatureConfiguration): SignOutput {
        val signInput = determineSignInput(origData, kid, signMode, signatureConfiguration)
        val signature = createSignature(signInput, kid)

        return sign(origData, signature, signatureConfiguration)
    }

    override fun sign(origData: OrigData, signature: Signature, signatureConfiguration: SignatureConfiguration): SignOutput {
        val mergeSignatureResponse = restSigningClient.mergeSignature(MergeSignature()
            .origData(com.sphereon.vdx.ades.rest.client.model.OrigData()
                .name(origData.name)
                .content(origData.value)
                .mimeType(origData.mimeType)
            )
            .signature(com.sphereon.vdx.ades.rest.client.model.Signature()
                .value(signature.value)
                .algorithm(SignatureAlgorithm.valueOf(signature.algorithm.name))
                .signMode(com.sphereon.vdx.ades.rest.client.model.SignMode.valueOf(signature.signMode.name))
                .keyEntry(
                    KeyEntry()
                    .kid(signature.keyEntry.kid)
                    .encryptionAlgorithm(CryptoAlgorithm.valueOf(signature.keyEntry.encryptionAlgorithm.name))
                    .publicKey(com.sphereon.vdx.ades.rest.client.model.Key()
                        .value(signature.keyEntry.publicKey.value)
                        .format(signature.keyEntry.publicKey.format)
                        .algorithm(CryptoAlgorithm.valueOf(signature.keyEntry.publicKey.algorithm.name))
                    )
                    .providerId(signature.providerId)
                    .certificate(com.sphereon.vdx.ades.rest.client.model.Certificate()
                        .value(signature.keyEntry.certificate?.value)
                        .serialNumber(signature.keyEntry.certificate?.serialNumber)
                        .issuerDN(signature.keyEntry.certificate?.issuerDN)
                        .subjectDN(signature.keyEntry.certificate?.subjectDN)
                        .notBefore(signature.keyEntry.certificate?.notBefore?.let { java.time.Instant.ofEpochSecond(it.epochSeconds) })
                        .notAfter(signature.keyEntry.certificate?.notAfter?.let { java.time.Instant.ofEpochSecond(it.epochSeconds) })
                        .fingerPrint(signature.keyEntry.certificate?.fingerPrint)
                    )
                )
                .date(java.time.Instant.ofEpochSecond(signature.date.epochSeconds))
                .binding(com.sphereon.vdx.ades.rest.client.model.ConfigKeyBinding()
                    .kid(signature.keyEntry.kid)
                    .keyProviderId(signature.providerId)
                )
            ))

        return signOutputFrom(mergeSignatureResponse.signOutput)
    }

    private fun getKey(kid: String): IKeyEntry {
        return keyProvider.getKey(kid) ?: throw PKIException("Could not retrieve key entry for kid $kid")
    }

    private fun signInputFrom(signInput: com.sphereon.vdx.ades.rest.client.model.SignInput): SignInput {
        return SignInput(
            input = signInput.input,
            signMode = SignMode.valueOf(signInput.signMode.name),
            signingDate = Instant.fromEpochSeconds(signInput.signingDate.epochSecond),
            digestAlgorithm = DigestAlg.valueOf(signInput.digestAlgorithm.name),
            name = signInput.name,
            binding = ConfigKeyBinding(
                kid = signInput.binding.kid,
                signatureConfigId = signInput.binding.signatureConfigId,
                keyProviderId = signInput.binding.keyProviderId
            )
        )
    }

    private fun signOutputFrom(signOutput: com.sphereon.vdx.ades.rest.client.model.SignOutput): SignOutput {
        return SignOutput(
            value = signOutput.value,
            signMode = com.sphereon.vdx.ades.enums.SignMode.valueOf(signOutput.signature.signMode.name),
            digestAlgorithm = DigestAlg.valueOf(signOutput.digestAlgorithm.name),
            name = signOutput.name,
            mimeType = signOutput.mimeType,
            signature = Signature(
                value = signOutput.signature.value,
                algorithm = SignatureAlg.valueOf(signOutput.signature.algorithm.name),
                signMode = com.sphereon.vdx.ades.enums.SignMode.valueOf(signOutput.signature.signMode.name),
                keyEntry = com.sphereon.vdx.ades.model.KeyEntry(
                    kid = signOutput.signature.keyEntry.kid,
                    publicKey = Key(
                        algorithm = CryptoAlg.valueOf(signOutput.signature.keyEntry.publicKey.algorithm.name),
                        value = signOutput.signature.keyEntry.publicKey.value,
                        format = signOutput.signature.keyEntry.publicKey.format,
                    ),
                    encryptionAlgorithm = CryptoAlg.valueOf(signOutput.signature.keyEntry.encryptionAlgorithm.name),
                    certificate = com.sphereon.vdx.ades.model.Certificate(
                        value = signOutput.signature.keyEntry.certificate.value,
                        serialNumber = signOutput.signature.keyEntry.certificate.serialNumber,
                        issuerDN = signOutput.signature.keyEntry.certificate.issuerDN,
                        subjectDN = signOutput.signature.keyEntry.certificate.subjectDN,
                        notBefore = Instant.fromEpochSeconds(signOutput.signature.keyEntry.certificate.notBefore.epochSecond),
                        notAfter = Instant.fromEpochSeconds(signOutput.signature.keyEntry.certificate.notAfter.epochSecond),
                        fingerPrint = signOutput.signature.keyEntry.certificate.fingerPrint
                    ),
                    certificateChain = signOutput.signature.keyEntry.certificateChain.map {
                        com.sphereon.vdx.ades.model.Certificate(
                            value = it.value,
                            serialNumber = it.serialNumber,
                            issuerDN = it.issuerDN,
                            subjectDN = it.subjectDN,
                            notBefore = Instant.fromEpochSeconds(it.notBefore.epochSecond),
                            notAfter = Instant.fromEpochSeconds(it.notAfter.epochSecond),
                            fingerPrint = it.fingerPrint
                        )
                    }
                ),
                providerId = signOutput.signature.binding.keyProviderId,
                date = Instant.fromEpochSeconds(signOutput.signature.date.epochSecond)
            )
        )
    }

}
