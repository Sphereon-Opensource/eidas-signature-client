package com.sphereon.vdx.ades.enums

@kotlinx.serialization.Serializable
enum class SignaturePackaging {
    /** The signature is enveloped to the signed document  */
    ENVELOPED,

    /** The signature envelops the signed document  */
    ENVELOPING,

    /** The signature is detached from the signed document  */
    DETACHED,

    /** The signature file contains the signed document (XAdES only)  */
    INTERNALLY_DETACHED
}
