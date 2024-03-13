package com.sphereon.vdx.ades.sign.util

import com.sphereon.vdx.ades.SignClientException
import com.sphereon.vdx.ades.SigningException
import com.sphereon.vdx.ades.enums.*
import com.sphereon.vdx.ades.enums.ImageScaling
import com.sphereon.vdx.ades.enums.SignatureForm
import com.sphereon.vdx.ades.enums.SignatureLevel
import com.sphereon.vdx.ades.enums.SignaturePackaging
import com.sphereon.vdx.ades.enums.SignerTextHorizontalAlignment
import com.sphereon.vdx.ades.enums.SignerTextPosition
import com.sphereon.vdx.ades.enums.SignerTextVerticalAlignment
import com.sphereon.vdx.ades.enums.TextWrapping
import com.sphereon.vdx.ades.enums.VisualSignatureAlignmentHorizontal
import com.sphereon.vdx.ades.enums.VisualSignatureAlignmentVertical
import com.sphereon.vdx.ades.enums.VisualSignatureRotation
import com.sphereon.vdx.ades.model.*
import com.sphereon.vdx.ades.pki.DSSWrappedKeyEntry
import com.sphereon.vdx.ades.pki.azure.AzureKeyvaultClientConfig
import com.sphereon.vdx.ades.pki.azure.AzureKeyvaultTokenConnection
import com.sphereon.vdx.pkcs7.PKCS7Service
import com.sphereon.vdx.pkcs7.PKCS7SignatureParameters
import eu.europa.esig.dss.AbstractSignatureParameters
import eu.europa.esig.dss.cades.CAdESSignatureParameters
import eu.europa.esig.dss.cades.signature.CAdESService
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters
import eu.europa.esig.dss.enumerations.*
import eu.europa.esig.dss.enumerations.CertificationPermission
import eu.europa.esig.dss.jades.signature.JAdESService
import eu.europa.esig.dss.model.*
import eu.europa.esig.dss.model.TimestampParameters
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.pades.*
import eu.europa.esig.dss.pades.signature.PAdESService
import eu.europa.esig.dss.service.tsp.OnlineTSPSource
import eu.europa.esig.dss.signature.AbstractSignatureService
import eu.europa.esig.dss.token.DSSPrivateKeyEntry
import eu.europa.esig.dss.token.KSPrivateKeyEntry
import eu.europa.esig.dss.token.Pkcs11SignatureToken
import eu.europa.esig.dss.token.Pkcs12SignatureToken
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.datetime.toJavaInstant
import java.awt.Color
import java.lang.reflect.Field
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
        kid = this.alias,
//        attributes = if (this.attributes != null) null else null,
        publicKey = this.certificate.publicKey.toKey(),
        privateKey = Key(value = this.privateKey.encoded, algorithm = CryptoAlg.valueOf(this.privateKey.algorithm), format = this.privateKey.format),
        certificate = this.certificate.certificate.toCertificate(),
        certificateChain = this.certificateChain.map { it.toCertificate() },
        encryptionAlgorithm = this.certificate.signatureAlgorithm.encryptionAlgorithm.fromDSS()
    )
}

fun DSSPrivateKeyEntry.fromDSS(kid: String): IKeyEntry {
    return when (this) {
        is KSPrivateKeyEntry -> this.fromDSS()
        else -> KeyEntry(
            kid = kid,
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
            return KSPrivateKeyEntry(this.kid, this.toJavaPrivateKeyEntry())
        else -> DSSWrappedKeyEntry(this)
    }
}

/*fun IPrivateKeyEntry.toDSS(): DSSPrivateKeyEntry {
    // for now, we just always assume a KS Private Key
    return KSPrivateKeyEntry(this.kid, this.toJavaPrivateKeyEntry())
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

fun AzureKeyvaultClientConfig.toAzureSignatureToken(kid: String): AzureKeyvaultTokenConnection {
    return AzureKeyvaultTokenConnection(this, kid)
}


fun X509Certificate.toCertificate(): Certificate {
    return CertificateUtil.toCertificate(this)
}

fun PublicKey.toKey(): Key {
    return Key(algorithm = CryptoAlg.from(algorithm), value = encoded, format = format)
}

fun X509Certificate.toPublicKey(): Key {
    return publicKey.toKey()
}

fun Certificate.toX509Certificate(): X509Certificate {
    return CertificateUtil.toX509Certificate(this)
}
fun Certificate.isActive(): Boolean {
    val now = Clock.System.now()
    return now in notBefore..notAfter
}

fun Pkcs11Parameters.toPkcs11SignatureToken(): Pkcs11SignatureToken {
    return Pkcs11SignatureToken("FIXME")
}


fun PasswordInputCallback.toDSS(): PasswordProtection {
    return if (this.protectionParameters == null) PasswordProtection(this.password) else PasswordProtection(
        password, protectionAlgorithm, protectionParameters as AlgorithmParameterSpec?
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

fun SignatureValue.fromDSS(signMode: SignMode, keyEntry: IKeyEntry, providerId: String, signingDate: Instant): Signature {
    return Signature(
        value = this.value,
        signMode = signMode,
        algorithm = this.algorithm.fromDSS(),
        keyEntry = keyEntry,
        providerId = providerId,
        date = signingDate
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

fun AbstractSignatureService<out AbstractSignatureParameters<out TimestampParameters>, out TimestampParameters>.toPAdESService(
    timestampParameters: com.sphereon.vdx.ades.model.TimestampParameters?
): PAdESService {
    val padesService = this as PAdESService
    if (timestampParameters != null) {
        padesService.setTspSource(OnlineTSPSource(timestampParameters.tsaUrl))
    }

    return padesService
}

fun AbstractSignatureService<out AbstractSignatureParameters<out TimestampParameters>, out TimestampParameters>.toPKCS7Service(timestampParameters: com.sphereon.vdx.ades.model.TimestampParameters?): PKCS7Service {
    val pkcS7Service = this as PKCS7Service
    if (timestampParameters != null) {
        pkcS7Service.setTspSource(OnlineTSPSource(timestampParameters.tsaUrl))
    }
    return pkcS7Service
}

fun OrigData.toDSSDocument(): DSSDocument {
    return InMemoryDocument(this.value, name, MimeType.fromMimeTypeString(mimeType))
}

fun VisualSignatureParameters.toDSS(): SignatureImageParameters {
    val parameters = SignatureImageParameters()

    parameters.image = image?.toDSSDocument()
    parameters.fieldParameters = fieldParameters?.toDSS()
    parameters.textParameters = textParameters?.toDSS()
    parameters.dpi = dpi
    parameters.textParameters = textParameters?.toDSS()
    parameters.imageScaling = imageScaling?.toDSS()
    parameters.backgroundColor = stringToColor(backgroundColor, Color.WHITE)
    parameters.rotation = rotation?.toDSS()
    parameters.zoom = zoom
    if (alignmentHorizontal != null) {
        parameters.setAlignmentHorizontal(alignmentHorizontal.toDSS())
    }
    if (alignmentVertical != null) {
        parameters.setAlignmentVertical(alignmentVertical.toDSS())
    }
    return parameters
}


fun VisualSignatureTextParameters.toDSS(): SignatureImageTextParameters {
    val parameters = SignatureImageTextParameters()
    parameters.text = text

    // TODO: font!
    parameters.backgroundColor = stringToColor(backgroundColor, Color.WHITE)
    parameters.padding = padding
    parameters.signerTextHorizontalAlignment = signerTextHorizontalAlignment.toDSS()
    parameters.signerTextVerticalAlignment = signerTextVerticalAlignment.toDSS()
    parameters.signerTextPosition = signerTextPosition.toDSS()
    parameters.textColor = stringToColor(textColor, Color.BLACK)
    parameters.textWrapping = textWrapping.toDSS()

    return parameters
}

private fun stringToColor(value: String?, defaultValue: Color): Color? {
    return if (value == null) {
        defaultValue
    } else try {
        // get color by hex or octal value
        Color.decode(value)
    } catch (nfe: NumberFormatException) {
        // if we can't decode lets try to get it by name
        try {
            // try to get a color by name using reflection
            val f: Field = Color::class.java.getField(value.lowercase())
            f.get(null) as Color
        } catch (ce: Exception) {
            // if we can't get any color return black
            defaultValue
        }
    }
}

fun VisualSignatureFieldParameters.toDSS(): SignatureFieldParameters {
    val parameters = SignatureFieldParameters()
    parameters.height = height
    parameters.width = width
    parameters.fieldId = fieldId
    parameters.originX = originX
    parameters.originY = originY
    parameters.page = page
    return parameters
}

fun ImageScaling.toDSS(): eu.europa.esig.dss.enumerations.ImageScaling {
    return eu.europa.esig.dss.enumerations.ImageScaling.valueOf(this.name)
}

fun VisualSignatureRotation.toDSS(): eu.europa.esig.dss.enumerations.VisualSignatureRotation {
    return eu.europa.esig.dss.enumerations.VisualSignatureRotation.valueOf(name)
}

fun VisualSignatureAlignmentHorizontal.toDSS(): eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal {
    return eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal.valueOf(name)
}

fun VisualSignatureAlignmentVertical.toDSS(): eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical {
    return eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical.valueOf(name)
}

fun SignerTextHorizontalAlignment.toDSS(): eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment {
    return eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment.valueOf(name)
}

fun SignerTextVerticalAlignment.toDSS(): eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment {
    return eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment.valueOf(name)
}

fun SignerTextPosition.toDSS(): eu.europa.esig.dss.enumerations.SignerTextPosition {
    return eu.europa.esig.dss.enumerations.SignerTextPosition.valueOf(name)
}

fun TextWrapping.toDSS(): eu.europa.esig.dss.enumerations.TextWrapping {
    return eu.europa.esig.dss.enumerations.TextWrapping.valueOf(name)
}

fun SignatureParameters.toDSS(
    key: IKeyEntry,
    signedData: ByteArray? = null,
    signatureAlg: SignatureAlg? = null,
    timestampParameters: com.sphereon.vdx.ades.model.TimestampParameters? = null,
    signingDate: Instant? = null
): AbstractSignatureParameters<out SerializableTimestampParameters> {
    return when (signatureForm()) {
        SignatureForm.CAdES -> toCades(key, signedData, signingDate, signatureAlg, timestampParameters)
        SignatureForm.PAdES -> toPades(key, signedData, signingDate, signatureAlg, timestampParameters)
        SignatureForm.PKCS7 -> toPKCS7(key, signingDate, timestampParameters)
        else -> throw SigningException("Encryption algorithm $encryptionAlgorithm not supported yet")
    }
}

fun SignatureParameters.toCades(
    key: IKeyEntry,
    signedData: ByteArray? = null,
    signingDate: Instant? = null,
    signatureAlg: SignatureAlg? = null,
    timestampParameters: com.sphereon.vdx.ades.model.TimestampParameters?
): CAdESSignatureParameters {
    if (signatureForm() != SignatureForm.CAdES) throw SigningException("Cannot convert to cades signature parameters when signature form is ${signatureForm()}")
    return mapCadesSignatureParams(this, key, signingDate, signedData, signatureAlg, timestampParameters)
}

fun SignatureParameters.toPades(
    key: IKeyEntry,
    signedData: ByteArray? = null,
    signingDate: Instant? = null,
    signatureAlg: SignatureAlg? = null,
    timestampParameters: com.sphereon.vdx.ades.model.TimestampParameters?
): PAdESSignatureParameters {
    if (signatureForm() != SignatureForm.PAdES) throw SigningException("Cannot convert to pades signature parameters when signature form is ${signatureForm()}")
    return mapPadesSignatureParams(this, key, signingDate, signedData, signatureAlg, timestampParameters)
}

fun mapPadesSignatureParams(
    signatureParameters: SignatureParameters,
    key: IKeyEntry,
    signingDate: Instant? = null,
    signedData: ByteArray? = null,
    signatureAlg: SignatureAlg? = null,
    timestampParameters: com.sphereon.vdx.ades.model.TimestampParameters?
): PAdESSignatureParameters {
    val dssParams = PAdESSignatureParameters()

    mapTimestampParams(dssParams, signatureForm = signatureParameters.signatureForm(), timestampParameters = timestampParameters)
    mapBlevelParams(dssParams.bLevel(), signatureParameters, signingDate)
    mapGenericSignatureParams(dssParams, signatureParameters, key, signedData, signatureAlg)
    dssParams.isEn319122 = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.en319122 ?: true
//    dssParams.contentHintsDescription = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.contentHintsDescription
//    dssParams.contentHintsType = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.contentHintsType
//    dssParams.contentIdentifierPrefix = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.contentIdentifierPrefix
//    dssParams.contentIdentifierSuffix = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.contentIdentifierSuffix

    dssParams.permission =
        if (signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.certificationPermission != null) eu.europa.esig.dss.enumerations.CertificationPermission.valueOf(
            signatureParameters.signatureFormParameters.padesSignatureFormParameters.certificationPermission.name
        ) else null
    dssParams.signerName = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.signerName
    dssParams.contactInfo = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.contactInfo
    dssParams.location = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.location
    dssParams.reason = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.reason
    dssParams.filter = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.signatureFilter
    dssParams.subFilter = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.signatureSubFilter
    dssParams.contentSize = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.signatureSize ?: 9472

    dssParams.imageParameters = signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.visualSignatureParameters?.toDSS()

    if (signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.mode != PdfSignatureMode.CERTIFICATION && dssParams.permission != null) {
        throw SigningException("Cannot set certification permissions when mode is not set to Certification")
    } else if (signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.mode == PdfSignatureMode.CERTIFICATION && dssParams.permission == null) {
        dssParams.permission = CertificationPermission.MINIMAL_CHANGES_PERMITTED
    }
    signatureParameters.signatureFormParameters?.padesSignatureFormParameters?.signingTimeZone?.let {
        dssParams.signingTimeZone = TimeZone.getTimeZone(it)
    }

    return dssParams
}

fun mapBlevelParams(dssbLevelParams: BLevelParameters, signatureParameters: SignatureParameters, signingDate: Instant? = null) {
    val bLevelParameters = signatureParameters.signatureLevelParameters?.bLevelParameters ?: return
    with(dssbLevelParams) {
        this.signingDate = if (signingDate != null) {
            bLevelParameters.signingDate = signingDate
            Date.from(signingDate.toJavaInstant())
        } else if (bLevelParameters.signingDate != null) {
            Date.from(bLevelParameters.signingDate!!.toJavaInstant())
        } else {
            null
        }
        isTrustAnchorBPPolicy = bLevelParameters.trustAnchorBPPolicy == true
        claimedSignerRoles = bLevelParameters.claimedSignerRoles
        if (bLevelParameters.signerLocationCountry != null || bLevelParameters.signerLocationLocality != null || bLevelParameters.signerLocationStreet != null || bLevelParameters.signerLocationPostalAddress != null || bLevelParameters.signerLocationPostalCode != null || bLevelParameters.signerLocationStateOrProvince != null) {
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
    signingDate: Instant?,
    signedData: ByteArray? = null,
    signatureAlg: SignatureAlg? = null,
    timestampParameters: com.sphereon.vdx.ades.model.TimestampParameters?
): CAdESSignatureParameters {
    val dssParams = CAdESSignatureParameters()
    dssParams.contentTimestampParameters = CAdESTimestampParameters()
    dssParams.signatureTimestampParameters = CAdESTimestampParameters()
    dssParams.archiveTimestampParameters = CAdESTimestampParameters()

    mapTimestampParams(dssParams, signatureParameters.signatureForm(), timestampParameters)
    mapGenericSignatureParams(dssParams, signatureParameters, key, signedData, signatureAlg)
    mapBlevelParams(dssParams.bLevel(), signatureParameters, signingDate)
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
            if (signatureAlg?.digestAlgorithm != null) signatureAlg.digestAlgorithm.toDSS() else signatureParameters.digestAlgorithm?.toDSS()
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
    signatureForm: SignatureForm,
    timestampParameters: com.sphereon.vdx.ades.model.TimestampParameters?,
) {
    val pades = signatureForm == SignatureForm.PAdES
    timestampParameters?.baselineBContentTimestampParameters?.apply {
        val tsParams = initTimestampParameters(pades)
        tsParams.digestAlgorithm = timestampParameters.baselineBContentTimestampParameters.digestAlgorithm.toDSS()
        if (pades && visualSignatureParameters != null) (tsParams as PAdESTimestampParameters).imageParameters = visualSignatureParameters.toDSS()
    }
    timestampParameters?.baselineTSignatureTimestampParameters?.apply {
        val tsParams = initTimestampParameters(pades)
        tsParams.digestAlgorithm = timestampParameters.baselineTSignatureTimestampParameters.digestAlgorithm.toDSS()
        dssParams.signatureTimestampParameters = tsParams
    }
    timestampParameters?.baselineLTAArchiveTimestampParameters?.apply {
        val tsParams = initTimestampParameters(pades)
        tsParams.digestAlgorithm = timestampParameters.baselineLTAArchiveTimestampParameters.digestAlgorithm.toDSS()
        dssParams.archiveTimestampParameters = tsParams
    }
    /*dssParams.contentTimestamps
    if (signatureParameters.timestampParameters?.contentTimestamps?.isNotEmpty() == true) {
        signatureParameters.timestampParameters.contentTimestamps.map {  }

    }*/


}

private fun initTimestampParameters(pades: Boolean) =
    if (pades) PAdESTimestampParameters().also { it.contentSize = 12314 } else CAdESTimestampParameters()

fun SignatureParameters.toPKCS7(
    key: IKeyEntry,
    signingDate: Instant? = null,
    timestampParameters: com.sphereon.vdx.ades.model.TimestampParameters? = null
): PKCS7SignatureParameters {
    if (signatureForm() != SignatureForm.PKCS7) throw SigningException("Cannot convert to PKCS7 signature parameters when signature form is ${signatureForm()}")
    return mapPKCSSignatureParams(this, key, signingDate, timestampParameters)
}

fun mapPKCSSignatureParams(
    signatureParameters: SignatureParameters,
    key: IKeyEntry,
    signingDate: Instant? = null,
    timestampParameters: com.sphereon.vdx.ades.model.TimestampParameters?
): PKCS7SignatureParameters {
    val dssParams = PKCS7SignatureParameters()
    dssParams.contentTimestampParameters = PAdESTimestampParameters()
    dssParams.signatureTimestampParameters = PAdESTimestampParameters()
    dssParams.archiveTimestampParameters = PAdESTimestampParameters()

    mapTimestampParams(dssParams, signatureParameters.signatureForm(), timestampParameters)
    mapGenericSignatureParams(dssParams, signatureParameters, key)
    mapBlevelParams(dssParams.bLevel(), signatureParameters, signingDate)
    signatureParameters.signatureFormParameters?.let { it ->
        it.pkcs7SignatureFormParameters?.let { formParameters ->
            dssParams.contactInfo = formParameters.contactInfo
            dssParams.location = formParameters.location
            dssParams.permission =
                if (formParameters.certificationPermission != null) eu.europa.esig.dss.enumerations.CertificationPermission.valueOf(
                    formParameters.certificationPermission.name
                ) else null
            dssParams.reason = formParameters.reason
            dssParams.signerName = formParameters.signerName
            dssParams.signatureMode = formParameters.mode

            if (dssParams.signatureMode != PdfSignatureMode.CERTIFICATION && dssParams.permission != null) {
                throw SigningException("Cannot set certification permissions when mode is not set to Certification")
            } else if (dssParams.signatureMode == PdfSignatureMode.CERTIFICATION && dssParams.permission == null) {
                dssParams.permission = CertificationPermission.MINIMAL_CHANGES_PERMITTED
            }
            signatureParameters.signatureFormParameters.padesSignatureFormParameters?.signingTimeZone?.let {
                dssParams.signingTimeZone = TimeZone.getTimeZone(it)
            }
        }
    }
    return dssParams
}

fun CertificateToken.toCertificate(): Certificate {
    return CertificateUtil.toCertificate(this.certificate)
}
