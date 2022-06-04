package com.sphereon.vdx.ades.enums

@kotlinx.serialization.Serializable
enum class SignatureAlg(val encryptionAlgorithm: CryptoAlg, val digestAlgorithm: DigestAlg? = null, val maskGenFunction: MaskGenFunction? = null) {
    RSA_RAW(CryptoAlg.RSA, null),

    RSA_SHA256(CryptoAlg.RSA, DigestAlg.SHA256),

    RSA_SHA512(CryptoAlg.RSA, DigestAlg.SHA512),

    RSA_SHA3_256(CryptoAlg.RSA, DigestAlg.SHA3_256),

    RSA_SHA3_512(CryptoAlg.RSA, DigestAlg.SHA3_512),

/*    DSA_SHA256(CryptoAlg.DSA, DigestAlg.SHA256),

    DSA_SHA512(CryptoAlg.DSA, DigestAlg.SHA512),*/

    RSA_SSA_PSS_RAW_MGF1(CryptoAlg.RSA, null, MaskGenFunction.MGF1),
    RSA_SSA_PSS_SHA256_MGF1(CryptoAlg.RSA, DigestAlg.SHA256, MaskGenFunction.MGF1),
    RSA_SSA_PSS_SHA512_MGF1(CryptoAlg.RSA, DigestAlg.SHA512, MaskGenFunction.MGF1),
    RSA_SSA_PSS_SHA3_256_MGF1(CryptoAlg.RSA, DigestAlg.SHA3_256, MaskGenFunction.MGF1),
    RSA_SSA_PSS_SHA3_512_MGF1(CryptoAlg.RSA, DigestAlg.SHA3_512, MaskGenFunction.MGF1),

}
