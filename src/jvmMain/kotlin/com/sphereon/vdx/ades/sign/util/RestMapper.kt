package com.sphereon.vdx.ades.sign.util

import com.sphereon.vdx.ades.enums.CryptoAlg
import com.sphereon.vdx.ades.enums.DigestAlg
import com.sphereon.vdx.ades.enums.SignMode
import com.sphereon.vdx.ades.enums.SignatureAlg
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.rest.client.model.CryptoAlgorithm
import kotlinx.datetime.Instant


fun com.sphereon.vdx.ades.rest.client.model.SignOutput.toLocalSignOutput(): SignOutput {
    return SignOutput(
        value = this.value,
        signMode = SignMode.valueOf(this.signature.signMode.name),
        digestAlgorithm = DigestAlg.valueOf(this.digestAlgorithm.name),
        name = this.name,
        mimeType = this.mimeType,
        signature = Signature(
            value = this.signature.value,
            algorithm = SignatureAlg.valueOf(this.signature.algorithm.name),
            signMode = SignMode.valueOf(this.signature.signMode.name),
            keyEntry = KeyEntry(
                kid = this.signature.keyEntry.kid,
                publicKey = Key(
                    algorithm = CryptoAlg.valueOf(this.signature.keyEntry.publicKey.algorithm.name),
                    value = this.signature.keyEntry.publicKey.value,
                    format = this.signature.keyEntry.publicKey.format,
                ),
                encryptionAlgorithm = CryptoAlg.valueOf(this.signature.keyEntry.encryptionAlgorithm.name),
                certificate = Certificate(
                    value = this.signature.keyEntry.certificate.value,
                    serialNumber = this.signature.keyEntry.certificate.serialNumber,
                    issuerDN = this.signature.keyEntry.certificate.issuerDN,
                    subjectDN = this.signature.keyEntry.certificate.subjectDN,
                    notBefore = Instant.fromEpochSeconds(this.signature.keyEntry.certificate.notBefore.epochSecond),
                    notAfter = Instant.fromEpochSeconds(this.signature.keyEntry.certificate.notAfter.epochSecond),
                    fingerPrint = this.signature.keyEntry.certificate.fingerPrint
                ),
                certificateChain = this.signature.keyEntry.certificateChain.map {
                    Certificate(
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
            providerId = this.signature.binding.keyProviderId,
            date = Instant.fromEpochSeconds(this.signature.date.epochSecond)
        )
    )
}

fun com.sphereon.vdx.ades.rest.client.model.SignInput.toLocalSignInput(): SignInput {
    return SignInput(
        name = this.name,
        input = this.input,
        signMode = SignMode.valueOf(this.signMode.name),
        digestAlgorithm = DigestAlg.valueOf(this.digestAlgorithm.name),
        signingDate = Instant.fromEpochSeconds(this.signingDate.epochSecond),
        binding = ConfigKeyBinding(
            kid = this.binding.kid,
            signatureConfigId = this.binding.signatureConfigId,
            keyProviderId = this.binding.keyProviderId
        )
    )
}

fun IKeyEntry.toRestClientKeyEntry(providerId: String): com.sphereon.vdx.ades.rest.client.model.KeyEntry {
    return com.sphereon.vdx.ades.rest.client.model.KeyEntry()
        .kid(this.kid)
        .encryptionAlgorithm(CryptoAlgorithm.valueOf(this.encryptionAlgorithm.name))
        .publicKey(com.sphereon.vdx.ades.rest.client.model.Key()
            .value(this.publicKey.value)
            .format(this.publicKey.format)
            .algorithm(CryptoAlgorithm.valueOf(this.publicKey.algorithm.name))
        )
        .providerId(providerId)
        .certificate(com.sphereon.vdx.ades.rest.client.model.Certificate()
            .value(this.certificate?.value)
            .serialNumber(this.certificate?.serialNumber)
            .issuerDN(this.certificate?.issuerDN)
            .subjectDN(this.certificate?.subjectDN)
            .notBefore(this.certificate?.notBefore?.let { java.time.Instant.ofEpochSecond(it.epochSeconds) })
            .notAfter(this.certificate?.notAfter?.let { java.time.Instant.ofEpochSecond(it.epochSeconds) })
            .fingerPrint(this.certificate?.fingerPrint)
        )
        .certificateChain(this.certificateChain?.map {
            com.sphereon.vdx.ades.rest.client.model.Certificate()
                .value(it.value)
                .serialNumber(it.serialNumber)
                .issuerDN(it.issuerDN)
                .subjectDN(it.subjectDN)
                .notBefore(it.notBefore.let { java.time.Instant.ofEpochSecond(it.epochSeconds) })
                .notAfter(it.notAfter.let { java.time.Instant.ofEpochSecond(it.epochSeconds) })
                .fingerPrint(it.fingerPrint)
        })
}

fun Signature.toRestClientSignature(): com.sphereon.vdx.ades.rest.client.model.Signature {
    return com.sphereon.vdx.ades.rest.client.model.Signature()
        .value(this.value)
        .algorithm(com.sphereon.vdx.ades.rest.client.model.SignatureAlgorithm.valueOf(this.algorithm.name))
        .signMode(com.sphereon.vdx.ades.rest.client.model.SignMode.valueOf(this.signMode.name))
        .keyEntry(this.keyEntry.toRestClientKeyEntry(this.providerId))
        .date(java.time.Instant.ofEpochSecond(this.date.epochSeconds))
        .binding(com.sphereon.vdx.ades.rest.client.model.ConfigKeyBinding()
            .kid(this.keyEntry.kid)
            .keyProviderId(this.providerId)
        )
}

fun OrigData.toRestClientOrigData(): com.sphereon.vdx.ades.rest.client.model.OrigData {
    return com.sphereon.vdx.ades.rest.client.model.OrigData()
        .name(this.name)
        .content(this.value)
        .mimeType(this.mimeType)
}

fun ConfigKeyBinding.toRestClientConfigKeyBinding(): com.sphereon.vdx.ades.rest.client.model.ConfigKeyBinding {
    return com.sphereon.vdx.ades.rest.client.model.ConfigKeyBinding()
        .kid(this.kid)
        .signatureConfigId(this.signatureConfigId)
        .keyProviderId(this.keyProviderId)
}

fun SignInput.toRestClientSignInput(): com.sphereon.vdx.ades.rest.client.model.SignInput {
    return com.sphereon.vdx.ades.rest.client.model.SignInput()
        .name(this.name)
        .input(this.input)
        .signMode(com.sphereon.vdx.ades.rest.client.model.SignMode.valueOf(this.signMode.name))
        .digestAlgorithm(this.digestAlgorithm?.name?.let { com.sphereon.vdx.ades.rest.client.model.DigestAlgorithm.valueOf(it) })
        .signingDate(java.time.Instant.ofEpochSecond(this.signingDate.epochSeconds))
        .binding(this.binding.toRestClientConfigKeyBinding())
}

