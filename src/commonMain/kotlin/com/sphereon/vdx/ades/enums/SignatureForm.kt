package com.sphereon.vdx.ades.enums

@kotlinx.serialization.Serializable
enum class SignatureForm {
    /** An XML-based signature according to EN 319 132 */
//    XAdES,

    /** A CMS-based signature according to EN 319 122 */
    CAdES,

    /** A JSON-based signature according to TS 119 182 */
    JAdES,

    /** A PDF-based signature according to EN 319 142 */
    PAdES,

    /** A PDF-based signature according to ISO 32000 */
    PKCS7,

    /** Simply sign a digest using the key */
    DIGEST,
}
