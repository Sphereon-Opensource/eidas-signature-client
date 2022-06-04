package com.sphereon.vdx.ades.enums


@kotlinx.serialization.Serializable
enum class DigestAlg(
    val internalName: String,
    val javaName: String,
    val oid: String,
    val xmlId: String? = null,
    val jadesId: String? = null,
    val httpHeaderId: String? = null,
    val saltLength: Int? = 0
) {
    NONE("", "", ""),
    SHA256("SHA256", "SHA-256", "2.16.840.1.101.3.4.2.1", "http://www.w3.org/2001/04/xmlenc#sha256", "S256", "SHA-256", 32),
    SHA512("SHA512", "SHA-512", "2.16.840.1.101.3.4.2.3", "http://www.w3.org/2001/04/xmlenc#sha512", "S512", "SHA-512", 64),
    SHA3_256("SHA3-256", "SHA3-256", "2.16.840.1.101.3.4.2.8", "http://www.w3.org/2007/05/xmldsig-more#sha3-256", "S3-256", null, 32),
    SHA3_512("SHA3-512", "SHA3-512", "2.16.840.1.101.3.4.2.10", "http://www.w3.org/2007/05/xmldsig-more#sha3-512", "S3-512", null, 64);

    companion object {
        fun isNone(digestAlg: DigestAlg?): Boolean {
            return digestAlg == null || digestAlg == NONE
        }
    }
}

@kotlinx.serialization.Serializable
enum class CryptoAlg(val internalName: String, val oid: String, val padding: String) {

    RSA("RSA", "1.2.840.113549.1.1.1", "RSA/ECB/PKCS1Padding"),

//    DSA("DSA", "1.2.840.10040.4.1", "DSA"),

    ECDSA("ECDSA", "1.2.840.10045.2.1", "ECDSA"),

//    PLAIN_ECDSA("PLAIN-ECDSA", "0.4.0.127.0.7.1.1.4.1", "PLAIN-ECDSA"),

    X25519("X25519", "1.3.101.110", "X25519"),

    X448("X448", "1.3.101.111", "X448"),

    ED25519("Ed25519", "1.3.101.112", "Ed25519"),

    ED448("Ed448", "1.3.101.113", "Ed448"),

    HMAC("HMAC", "", "");
}

