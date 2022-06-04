package com.sphereon.vdx.ades.sign.util

import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.SigningException
import com.sphereon.vdx.ades.enums.*
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.pki.AzureKeyvaultClientConfig
import com.sphereon.vdx.ades.pki.AzureKeyvaultTokenConnection
import com.sphereon.vdx.ades.pki.DSSWrappedKeyEntry
import eu.europa.esig.dss.AbstractSignatureParameters
import eu.europa.esig.dss.cades.CAdESSignatureParameters
import eu.europa.esig.dss.cades.signature.CAdESService
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters
import eu.europa.esig.dss.enumerations.DigestAlgorithm
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm
import eu.europa.esig.dss.enumerations.MaskGenerationFunction
import eu.europa.esig.dss.enumerations.SignatureAlgorithm
import eu.europa.esig.dss.jades.signature.JAdESService
import eu.europa.esig.dss.model.*
import eu.europa.esig.dss.model.TimestampParameters
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.pades.PAdESSignatureParameters
import eu.europa.esig.dss.pades.signature.PAdESService
import eu.europa.esig.dss.signature.AbstractSignatureService
import eu.europa.esig.dss.token.DSSPrivateKeyEntry
import eu.europa.esig.dss.token.KSPrivateKeyEntry
import eu.europa.esig.dss.token.Pkcs11SignatureToken
import eu.europa.esig.dss.token.Pkcs12SignatureToken
import kotlinx.datetime.toJavaInstant
import java.security.KeyFactory
import java.security.KeyStore
import java.security.KeyStore.PasswordProtection
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*


fun DigestAlg.toDSS(): DigestAlgorithm {
    return DigestAlgorithm.valueOf(name)
}

fun MaskGenFunction.toDSS(): MaskGenerationFunction {
    return MaskGenerationFunction.valueOf(name)
}

fun EncryptionAlgorithm.fromDSS(): CryptoAlg {
    return CryptoAlg.valueOf(name)
}

fun CryptoAlg.toDSS(): EncryptionAlgorithm {
    return EncryptionAlgorithm.valueOf(name)
}

fun SignatureAlgorithm.fromDSS(): SignatureAlg {
    return SignatureAlg.valueOf(name)
}

fun SignatureAlg.toDSS(): SignatureAlgorithm {
    return SignatureAlgorithm.valueOf(name)
}

fun SignatureLevel.toDSS(): eu.europa.esig.dss.enumerations.SignatureLevel {
    return eu.europa.esig.dss.enumerations.SignatureLevel.valueOf(name)
}

fun KSPrivateKeyEntry.fromDSS(): IPrivateKeyEntry {
    return PrivateKeyEntry(
        alias = this.alias,
//        attributes = if (this.attributes != null) null else null,
        publicKey = this.certificate.publicKey.toKey(),
        privateKey = Key(value = this.privateKey.encoded, algorithm = CryptoAlg.valueOf(this.privateKey.algorithm), format = this.privateKey.format),
        certificate = this.certificate.certificate.toCertificate(),
        certificateChain = this.certificateChain.map { it.toCertificate() },
        encryptionAlgorithm = this.certificate.signatureAlgorithm.encryptionAlgorithm.fromDSS()
    )
}

fun DSSPrivateKeyEntry.fromDSS(alias: String): IKeyEntry {
    return when (this) {
        is KSPrivateKeyEntry -> this.fromDSS()
        else -> KeyEntry(
            alias = alias,
            publicKey = this.certificate.publicKey.toKey(),
            certificate = this.certificate.toCertificate(),
            certificateChain = if (certificateChain == null) null else certificateChain.map { it.toCertificate() },
            encryptionAlgorithm = this.certificate.signatureAlgorithm.encryptionAlgorithm.fromDSS()
        )
    }
}

fun IKeyEntry.toDSS(): DSSPrivateKeyEntry {
    return when (this) {
        is IPrivateKeyEntry -> // for now, we just always assume a KS Private Key. We need this since most of DSS depends on this implementation
            return KSPrivateKeyEntry(this.alias, this.toJavaPrivateKeyEntry())
        else -> DSSWrappedKeyEntry(this)
    }
}

/*fun IPrivateKeyEntry.toDSS(): DSSPrivateKeyEntry {
    // for now, we just always assume a KS Private Key
    return KSPrivateKeyEntry(this.alias, this.toJavaPrivateKeyEntry())
}*/

fun IPrivateKeyEntry.toJavaPrivateKeyEntry(): KeyStore.PrivateKeyEntry {
    return KeyStore.PrivateKeyEntry(this.privateKey.toJavaPrivateKey(), this.certificateChain?.map { it.toX509Certificate() }?.toTypedArray())

}

fun Key.toJavaPublicKey(): PublicKey {
    // FIXME: Assumes x509
    val kf = KeyFactory.getInstance(algorithm.internalName)
    val keySpec = X509EncodedKeySpec(value)
    return kf.generatePublic(keySpec)
}

fun Key.toJavaPrivateKey(): PrivateKey {
    val kf = KeyFactory.getInstance(algorithm.internalName)
    val keySpec = PKCS8EncodedKeySpec(value)
    return kf.generatePrivate(keySpec)
}

fun KeystoreParameters.toPkcs12SignatureToken(callback: PasswordInputCallback): Pkcs12SignatureToken {
    return if (this.providerBytes != null) Pkcs12SignatureToken(providerBytes, callback.toDSS())
    else if (this.providerPath != null) Pkcs12SignatureToken(providerPath, callback.toDSS())
    else throw SignClientException("Please either provide bytes or a path for the keystore")
}

fun AzureKeyvaultClientConfig.toAzureSignatureToken(alias: String): AzureKeyvaultTokenConnection {
    return AzureKeyvaultTokenConnection(this, alias)
}


fun X509Certificate.toCertificate(): Certificate {
    return CertificateUtil.toCertificate(this)
}

fun PublicKey.toKey(): Key {
    return Key(algorithm = CryptoAlg.valueOf(algorithm), value = encoded, format = format)
}

fun X509Certificate.toPublicKey(): Key {
    return publicKey.toKey()
}

fun Certificate.toX509Certificate(): X509Certificate {
    return CertificateUtil.toX509Certificate(this)
}

fun Pkcs11Parameters.toPkcs11SignatureToken(): Pkcs11SignatureToken {
    return Pkcs11SignatureToken("FIXME")
}


fun PasswordInputCallback.toDSS(): PasswordProtection {
    return if (this.protectionParameters == null) PasswordProtection(this.password) else PasswordProtection(
        password,
        protectionAlgorithm,
        protectionParameters as AlgorithmParameterSpec?
    )

}


fun SignInput.toBeSigned(): ToBeSigned {
    return ToBeSigned(this.input)
}

fun SignInput.toDigest(): Digest {
    if (this.digestAlgorithm == null) throw SigningException("Digest algorithm is required when signinput is converted to digest")
    return Digest(this.digestAlgorithm.toDSS(), this.input)
}


fun Signature.toDSS(signatureAlgorithm: SignatureAlg?): SignatureValue {
    return SignatureValue(signatureAlgorithm?.toDSS() ?: algorithm.toDSS(), value)
}

fun SignatureValue.toRaw(): SignatureValue {
    val rawSigAlg = when (algorithm.encryptionAlgorithm) {
        EncryptionAlgorithm.RSA -> SignatureAlgorithm.RSA_RAW
        EncryptionAlgorithm.ECDSA -> SignatureAlgorithm.ECDSA_RAW
        EncryptionAlgorithm.DSA -> SignatureAlgorithm.DSA_RAW
        else -> algorithm
    }

    return SignatureValue(rawSigAlg, value)
}

fun SignatureValue.fromDSS(signMode: SignMode, keyEntry: IKeyEntry): Signature {
    return Signature(
        value = this.value,
        signMode = signMode,
        algorithm = this.algorithm.fromDSS(),
        keyEntry = keyEntry
    )
}

fun SignaturePackaging.toDSS(): eu.europa.esig.dss.enumerations.SignaturePackaging {
    return eu.europa.esig.dss.enumerations.SignaturePackaging.valueOf(name)
}

fun SignatureParameters.signatureForm(): SignatureForm {
    return signatureLevelParameters?.signatureLevel?.form
        ?: throw SigningException("Cannot deturm signature form when signature level params are not set")
}

fun AbstractSignatureService<out AbstractSignatureParameters<out TimestampParameters>, out TimestampParameters>.toCAdESService(): CAdESService {
    return this as CAdESService
}

fun AbstractSignatureService<out AbstractSignatureParameters<out TimestampParameters>, out TimestampParameters>.toJAdESService(): JAdESService {
    return this as JAdESService
}

fun AbstractSignatureService<out AbstractSignatureParameters<out TimestampParameters>, out TimestampParameters>.toPAdESService(): PAdESService {
    return this as PAdESService
}


fun SignatureParameters.toDSS(
    key: IKeyEntry,
    signedData: ByteArray? = null,
    signatureAlg: SignatureAlg? = null
): AbstractSignatureParameters<out SerializableTimestampParameters> {
    return when (signatureForm()) {
        SignatureForm.CAdES -> toCades(key, signedData, signatureAlg)
        SignatureForm.PAdES -> toPades(key, signedData, signatureAlg)
        else -> throw SigningException("Encryption algorithm $encryptionAlgorithm not supported yet")
    }
}

fun SignatureParameters.toCades(
    key: IKeyEntry,
    signedData: ByteArray? = null,
    signatureAlg: SignatureAlg? = null
): CAdESSignatureParameters {
    if (signatureForm() != SignatureForm.CAdES) throw SigningException("Cannot convert to cades signature parameters when signature form is ${signatureForm()}")
    return mapCadesSignatureParams(this, key, signedData, signatureAlg)
}

fun SignatureParameters.toPades(
    key: IKeyEntry,
    signedData: ByteArray? = null,
    signatureAlg: SignatureAlg? = null
): PAdESSignatureParameters {
    if (signatureForm() != SignatureForm.PAdES) throw SigningException("Cannot convert to pades signature parameters when signature form is ${signatureForm()}")
    return mapPadesSignatureParams(this, key, signedData, signatureAlg)
}

fun mapPadesSignatureParams(
    signatureParameters: SignatureParameters,
    key: IKeyEntry,
    signedData: ByteArray? = null,
    signatureAlg: SignatureAlg? = null
): PAdESSignatureParameters {
    val dssParams = PAdESSignatureParameters()
//    dssParams.contentTimestampParameters = PAdESTimestampParameters()
//    dssParams.signatureTimestampParameters = PAdESTimestampParameters()
//    dssParams.archiveTimestampParameters = PAdESTimestampParameters()

//    mapTimestampParams(dssParams, signatureParameters)
    mapBlevelParams(dssParams.bLevel(), signatureParameters)
    mapGenericSignatureParams(dssParams, signatureParameters, key, signedData, signatureAlg)
    dssParams.isEn319122 = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.en319122 ?: true
    dssParams.contentHintsDescription = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.contentHintsDescription
    dssParams.contentHintsType = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.contentHintsType
    dssParams.contentIdentifierPrefix = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.contentIdentifierPrefix
    dssParams.contentIdentifierSuffix = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.contentIdentifierSuffix

    dssParams.permission =
        if (signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.permission != null) eu.europa.esig.dss.enumerations.CertificationPermission.valueOf(
            signatureParameters.signatureFormParameters.padesSignatureFormParameters.permission.name
        ) else null
    dssParams.signerName = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.signerName
    dssParams.contactInfo = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.contactInfo
    dssParams.location = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.location
    dssParams.reason = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.reason
    dssParams.filter = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.signatureFilter
    dssParams.subFilter = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.signatureSubFilter
//    dssParams.signingTimeZone = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.

    return dssParams
}

fun mapBlevelParams(dssbLevelParams: BLevelParameters, signatureParameters: SignatureParameters) {
    val bLevelParameters = signatureParameters.signatureLevelParameters?.bLevelParameters ?: return
    with(dssbLevelParams) {
        signingDate = if (bLevelParameters.signingDate != null) Date.from(bLevelParameters.signingDate.toJavaInstant()) else null
        isTrustAnchorBPPolicy = bLevelParameters.trustAnchorBPPolicy == true
        claimedSignerRoles = bLevelParameters.claimedSignerRoles
        if (bLevelParameters.signerLocationCountry != null || bLevelParameters.signerLocationLocality != null || bLevelParameters.signerLocationStreet != null ||
            bLevelParameters.signerLocationPostalAddress != null || bLevelParameters.signerLocationPostalCode != null || bLevelParameters.signerLocationStateOrProvince != null
        ) {
            val location = SignerLocation()
            with(location) {
                country = bLevelParameters.signerLocationCountry
                locality = bLevelParameters.signerLocationLocality
                streetAddress = bLevelParameters.signerLocationStreet
                postalAddress = bLevelParameters.signerLocationPostalAddress
                postalCode = bLevelParameters.signerLocationPostalCode
                stateOrProvince = bLevelParameters.signerLocationStateOrProvince

            }
            signerLocation = location
        }
    }

    // FXIME: Finish params
}

fun mapCadesSignatureParams(
    signatureParameters: SignatureParameters,
    key: IKeyEntry,
    signedData: ByteArray? = null,
    signatureAlg: SignatureAlg? = null
): CAdESSignatureParameters {
    val dssParams = CAdESSignatureParameters()
    dssParams.contentTimestampParameters = CAdESTimestampParameters()
    dssParams.signatureTimestampParameters = CAdESTimestampParameters()
    dssParams.archiveTimestampParameters = CAdESTimestampParameters()

    mapTimestampParams(dssParams, signatureParameters)
    mapGenericSignatureParams(dssParams, signatureParameters, key, signedData, signatureAlg)
    mapBlevelParams(dssParams.bLevel(), signatureParameters)
    dssParams.isEn319122 = signatureParameters.signatureFormParameters?.cadesSignatureFormParameters?.en319122 ?: true
    dssParams.contentHintsDescription = signatureParameters.signatureFormParameters?.cadesSignatureFormParameters?.contentHintsDescription
    dssParams.contentHintsType = signatureParameters.signatureFormParameters?.cadesSignatureFormParameters?.contentHintsType
    dssParams.contentIdentifierPrefix = signatureParameters.signatureFormParameters?.cadesSignatureFormParameters?.contentIdentifierPrefix
    dssParams.contentIdentifierSuffix = signatureParameters.signatureFormParameters?.cadesSignatureFormParameters?.contentIdentifierSuffix

    return dssParams
}


fun mapGenericSignatureParams(
    dssParams: AbstractSignatureParameters<out SerializableTimestampParameters>,
    signatureParameters: SignatureParameters,
    key: IKeyEntry,
    signedData: ByteArray? = null,
    signatureAlg: SignatureAlg? = null
) {

    with(dssParams) {
        signaturePackaging = signatureParameters.signaturePackaging?.toDSS()
        signatureLevel = signatureParameters.signatureLevelParameters?.signatureLevel?.toDSS()
        /*if (signatureAlg != null) {
            if (signatureAlg.digestAlgorithm != null) {
                digestAlgorithm = signatureAlg.digestAlgorithm.toDSS()
            } // No else, since the sig alg setter has a null check, whilst RAW sigs need this value to be null
        } else {
            digestAlgorithm = signatureParameters.digestAlgorithm?.toDSS()
        }
        signatureAlgorithm = SignatureAlgorithm.RSA_RAW*/
        digestAlgorithm =
            if (signatureAlg?.digestAlgorithm != null) signatureAlg.digestAlgorithm?.toDSS() else signatureParameters.digestAlgorithm?.toDSS()
        encryptionAlgorithm =
            if (signatureAlg?.encryptionAlgorithm != null) signatureAlg.encryptionAlgorithm.toDSS() else signatureParameters.encryptionAlgorithm?.toDSS()
        maskGenerationFunction =
            if (signatureAlg != null) signatureAlg.maskGenFunction?.toDSS() else signatureParameters.maskGenerationFunction?.toDSS()
        isCheckCertificateRevocation = signatureParameters.checkCertificateRevocation ?: false
        isSignWithExpiredCertificate = signatureParameters.signWithExpiredCertificate ?: false
        isSignWithNotYetValidCertificate = signatureParameters.signWithNotYetValidCertificate ?: false

        if (signatureParameters.signingCertificate == null && key.certificate != null) {
            this.signingCertificate = CertificateToken(key.certificate!!.toX509Certificate())
        }
        if ((signatureParameters.certificateChain == null || signatureParameters.certificateChain.isEmpty()) && key.certificateChain != null) {
            this.certificateChain = key.certificateChain!!.map { CertificateToken(it.toX509Certificate()) }
        }
        this.signedData = signedData
    }
}

fun mapTimestampParams(
    dssParams: AbstractSignatureParameters<out SerializableTimestampParameters>,
    signatureParameters: SignatureParameters,
) {
    if (signatureParameters.timestampParameters?.contentTimestampParameters != null) {
        ((dssParams.contentTimestampParameters) as TimestampParameters).digestAlgorithm =
            signatureParameters.timestampParameters.contentTimestampParameters.digestAlgorithm.toDSS()
    }
    if (signatureParameters.timestampParameters?.archiveTimestampParameters != null) {
        ((dssParams.archiveTimestampParameters) as TimestampParameters).digestAlgorithm =
            signatureParameters.timestampParameters.archiveTimestampParameters.digestAlgorithm.toDSS()
    }
    if (signatureParameters.timestampParameters?.signatureTimestampParameters != null) {
        ((dssParams.signatureTimestampParameters) as TimestampParameters).digestAlgorithm =
            signatureParameters.timestampParameters.signatureTimestampParameters.digestAlgorithm.toDSS()
    }

}

fun CertificateToken.toCertificate(): Certificate {
    return CertificateUtil.toCertificate(this.certificate)
}
