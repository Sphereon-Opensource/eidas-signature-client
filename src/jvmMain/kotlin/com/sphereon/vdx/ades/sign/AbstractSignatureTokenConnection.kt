package com.sphereon.vdx.ades.sign

import eu.europa.esig.dss.enumerations.DigestAlgorithm
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm
import eu.europa.esig.dss.enumerations.MaskGenerationFunction
import eu.europa.esig.dss.enumerations.SignatureAlgorithm
import eu.europa.esig.dss.model.DSSException
import eu.europa.esig.dss.model.Digest
import eu.europa.esig.dss.model.SignatureValue
import eu.europa.esig.dss.model.ToBeSigned
import eu.europa.esig.dss.token.DSSPrivateKeyEntry
import eu.europa.esig.dss.token.KSPrivateKeyEntry
import eu.europa.esig.dss.token.SignatureTokenConnection
import mu.KotlinLogging
import java.security.GeneralSecurityException
import java.security.NoSuchAlgorithmException
import java.security.Signature
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.*

private val logger = KotlinLogging.logger {}

abstract class AbstractSignatureTokenConnection : SignatureTokenConnection {


    @Throws(DSSException::class)
    override fun sign(toBeSigned: ToBeSigned, digestAlgorithm: DigestAlgorithm?, keyEntry: DSSPrivateKeyEntry): SignatureValue? {
        return sign(toBeSigned, digestAlgorithm, null, keyEntry)
    }

    @Throws(DSSException::class)
    override fun sign(
        toBeSigned: ToBeSigned, digestAlgorithm: DigestAlgorithm?, mgf: MaskGenerationFunction?,
        keyEntry: DSSPrivateKeyEntry
    ): SignatureValue? {
        val encryptionAlgorithm = keyEntry.encryptionAlgorithm
        val signatureAlgorithm = getSignatureAlgorithm(encryptionAlgorithm, digestAlgorithm, mgf)
        return sign(toBeSigned, signatureAlgorithm, keyEntry)
    }

    @Throws(DSSException::class)
    override fun sign(toBeSigned: ToBeSigned, signatureAlgorithm: SignatureAlgorithm, keyEntry: DSSPrivateKeyEntry): SignatureValue? {
        assertEncryptionAlgorithmValid(signatureAlgorithm, keyEntry)
        val javaSignatureAlgorithm = signatureAlgorithm.jceId
        val bytes = toBeSigned.bytes
        var param: AlgorithmParameterSpec? = null
        if (signatureAlgorithm.maskGenerationFunction != null) {
            param = createPSSParam(signatureAlgorithm.digestAlgorithm)
        }
        try {
            val signatureValue = sign(bytes, javaSignatureAlgorithm, param, keyEntry)
            val value = SignatureValue()
            value.algorithm = signatureAlgorithm
            value.value = signatureValue
            return value
        } catch (e: Exception) {
            throw DSSException(String.format("Unable to sign : %s", e.message), e)
        }
    }

    @Throws(DSSException::class)
    override fun signDigest(digest: Digest, keyEntry: DSSPrivateKeyEntry): SignatureValue? {
        return signDigest(digest, null as MaskGenerationFunction?, keyEntry)
    }

    @Throws(DSSException::class)
    override fun signDigest(digest: Digest, mgf: MaskGenerationFunction?, keyEntry: DSSPrivateKeyEntry): SignatureValue? {
        val encryptionAlgorithm = keyEntry.encryptionAlgorithm
        val signatureAlgorithm = getRawSignatureAlgorithm(encryptionAlgorithm, mgf)
        return signDigest(digest, signatureAlgorithm, keyEntry)
    }

    @Throws(DSSException::class)
    override fun signDigest(digest: Digest, signatureAlgorithm: SignatureAlgorithm, keyEntry: DSSPrivateKeyEntry): SignatureValue? {
        assertConfigurationValid(digest, signatureAlgorithm, keyEntry)
        val javaSignatureAlgorithm = getRawSignatureAlgorithm(
            signatureAlgorithm.encryptionAlgorithm, signatureAlgorithm.maskGenerationFunction
        ).jceId
        val digestedBytes = digest.value
        var param: AlgorithmParameterSpec? = null
        if (signatureAlgorithm.maskGenerationFunction != null) {
            param = createPSSParam(digest.algorithm)
        }
        try {
            val signatureValue = sign(digestedBytes, javaSignatureAlgorithm, param, keyEntry)
            val value = SignatureValue()
            value.algorithm = getSignatureAlgorithm(
                signatureAlgorithm.encryptionAlgorithm, digest.algorithm,
                signatureAlgorithm.maskGenerationFunction
            )
            value.value = signatureValue
            return value
        } catch (e: Exception) {
            throw DSSException(String.format("Unable to sign digest : %s", e.message), e)
        }
    }

    @Throws(GeneralSecurityException::class)
    open fun sign(
        bytes: ByteArray, javaSignatureAlgorithm: String, param: AlgorithmParameterSpec?,
        keyEntry: DSSPrivateKeyEntry
    ): ByteArray {
        if (keyEntry !is KSPrivateKeyEntry) {
            throw IllegalArgumentException("Only KSPrivateKeyEntry are supported")
        }
        val signature = getSignatureInstance(javaSignatureAlgorithm)
        if (param != null) {
            signature.setParameter(param)
        }
        signature.initSign(keyEntry.privateKey)
        signature.update(bytes)
        return signature.sign()
    }

    /**
     * This method returns a SignatureAlgorithm for the given configuration.
     * Throws an exception if no algorithm is found.
     *
     * @param encryptionAlgorithm [EncryptionAlgorithm]
     * @param digestAlgorithm [DigestAlgorithm]
     * @param maskGenerationFunction [MaskGenerationFunction]
     * @return [SignatureAlgorithm]
     */
    open fun getSignatureAlgorithm(
        encryptionAlgorithm: EncryptionAlgorithm, digestAlgorithm: DigestAlgorithm?,
        maskGenerationFunction: MaskGenerationFunction?
    ): SignatureAlgorithm {
        val signatureAlgorithm = SignatureAlgorithm.getAlgorithm(
            encryptionAlgorithm, digestAlgorithm, maskGenerationFunction
        )
            ?: throw UnsupportedOperationException(
                String.format(
                    "The SignatureAlgorithm is not found for the given configuration " +
                            "[EncryptionAlgorithm: %s; DigestAlgorithm: %s; MaskGenerationFunction: %s]",
                    encryptionAlgorithm, digestAlgorithm, maskGenerationFunction
                )
            )
        return signatureAlgorithm
    }

    /**
     * This method returns a RAW SignatureAlgorithm with null DigestAlgorithm value,
     * because the data to be signed is already digested
     *
     * @param encryptionAlgorithm [EncryptionAlgorithm]
     * @param maskGenerationFunction [MaskGenerationFunction]
     * @return [SignatureAlgorithm]
     */
    open fun getRawSignatureAlgorithm(
        encryptionAlgorithm: EncryptionAlgorithm,
        maskGenerationFunction: MaskGenerationFunction?
    ): SignatureAlgorithm {
        return SignatureAlgorithm.getAlgorithm(
            encryptionAlgorithm, null, maskGenerationFunction
        )
            ?: throw UnsupportedOperationException(
                String.format(
                    "The SignatureAlgorithm for digest signing is not found " +
                            "for the given configuration [EncryptionAlgorithm: %s; MaskGenerationFunction: %s]",
                    encryptionAlgorithm, maskGenerationFunction
                )
            )
    }

    /**
     * Returns the `java.security.Signature` instance for the given `javaSignatureAlgorithm`
     *
     * @param javaSignatureAlgorithm [String] representing the Java name of a signature algorithm
     * @return [Signature]
     * @throws NoSuchAlgorithmException if the algorithm is not found
     */
    @Throws(NoSuchAlgorithmException::class)
    protected open fun getSignatureInstance(javaSignatureAlgorithm: String?): Signature {
        return Signature.getInstance(javaSignatureAlgorithm)
    }

    /**
     * Creates `java.security.spec.AlgorithmParameterSpec` for the given `digestAlgo`
     *
     * @param digestAlgo [DigestAlgorithm]
     * @return [AlgorithmParameterSpec]
     */
    protected open fun createPSSParam(digestAlgo: DigestAlgorithm): AlgorithmParameterSpec? {
        val digestJavaName = digestAlgo.javaName
        return PSSParameterSpec(digestJavaName, "MGF1", MGF1ParameterSpec(digestJavaName), digestAlgo.saltLength, 1)
    }

    open fun assertConfigurationValid(digest: Digest, signatureAlgorithm: SignatureAlgorithm, keyEntry: DSSPrivateKeyEntry) {
        assertEncryptionAlgorithmValid(signatureAlgorithm, keyEntry)
        assertDigestAlgorithmValid(digest, signatureAlgorithm)
    }

    open fun assertEncryptionAlgorithmValid(signatureAlgorithm: SignatureAlgorithm, keyEntry: DSSPrivateKeyEntry) {
        Objects.requireNonNull(signatureAlgorithm, "SignatureAlgorithm shall be provided.")
        Objects.requireNonNull(signatureAlgorithm.encryptionAlgorithm, "EncryptionAlgorithm shall be provided within the SignatureAlgorithm.")
        Objects.requireNonNull(keyEntry, "keyEntry shall be provided.")
        if (!signatureAlgorithm.encryptionAlgorithm.isEquivalent(keyEntry.encryptionAlgorithm)) {
            throw IllegalArgumentException(
                String.format(
                    "The provided SignatureAlgorithm '%s' cannot be used to sign with " +
                            "the token's implied EncryptionAlgorithm '%s'", signatureAlgorithm.getName(), keyEntry.encryptionAlgorithm.getName()
                )
            )
        }
    }

    open fun assertDigestAlgorithmValid(digest: Digest, signatureAlgorithm: SignatureAlgorithm) {
        if (signatureAlgorithm.digestAlgorithm != null && signatureAlgorithm.digestAlgorithm != digest.algorithm) {
            throw IllegalArgumentException(
                String.format(
                    "The DigestAlgorithm '%s' provided withing a SignatureAlgorithm " +
                            "does not match the one used to compute the Digest : '%s'!",
                    signatureAlgorithm.digestAlgorithm.getName(), digest.algorithm.getName()
                )
            )
        }
    }
}
