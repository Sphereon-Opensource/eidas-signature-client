package com.sphereon.vdx.ades.enums

@kotlinx.serialization.Serializable
enum class JWSSerializationType {
    /**
     * 3.1.  JWS Compact Serialization Overview
     *
     * In the JWS Compact Serialization, no JWS Unprotected Header is used.
     * In this case, the JOSE Header and the JWS Protected Header are the
     * same.
     * In the JWS Compact Serialization, a JWS is represented as the
     * concatenation:
     *
     * BASE64URL(UTF8(JWS Protected Header)) || '.' ||
     * BASE64URL(JWS Payload) || '.' ||
     * BASE64URL(JWS Signature)
     */
    COMPACT_SERIALIZATION,

    /**
     * 7.2.1.  General JWS JSON Serialization Syntax
     *
     * The following members are defined for use in top-level JSON objects
     * used for the fully general JWS JSON Serialization syntax:
     *
     * payload
     *     The "payload" member MUST be present and contain the value
     *     BASE64URL(JWS Payload).
     *
     * signatures
     *     The "signatures" member value MUST be an array of JSON objects.
     *     Each object represents a signature or MAC over the JWS Payload and
     *     the JWS Protected Header.
     *
     * The following members are defined for use in the JSON objects that
     * are elements of the "signatures" array:
     *
     * protected
     *     The "protected" member MUST be present and contain the value
     *     BASE64URL(UTF8(JWS Protected Header)) when the JWS Protected
     *     Header value is non-empty; otherwise, it MUST be absent.  These
     *     Header Parameter values are integrity protected.
     *
     * header
     *     The "header" member MUST be present and contain the value JWS
     *     Unprotected Header when the JWS Unprotected Header value is non-
     *     empty; otherwise, it MUST be absent.  This value is represented as
     *     an unencoded JSON object, rather than as a string.  These Header
     *     Parameter values are not integrity protected.
     *
     * signature
     *     The "signature" member MUST be present and contain the value
     *     BASE64URL(JWS Signature).
     *
     * In summary, the syntax of a JWS using the general JWS JSON
     * Serialization is as follows:
     *
     * {@code
     *     {
     *      "payload":"<payload contents>",
     *       "signatures":[
     *        {"protected":"<integrity-protected header 1 contents>",
     *        "header":<non-integrity-protected header 1 contents>,
     *        "signature":"<signature 1 contents>"},
     *       ...
     *       {"protected":"<integrity-protected header N contents>",
     *        "header":<non-integrity-protected header N contents>,
     *        "signature":"<signature N contents>"}]
     *     }
     * }
     */
    JSON_SERIALIZATION,

    /**
     * 7.2.2.  Flattened JWS JSON Serialization Syntax
     *
     * The flattened JWS JSON Serialization syntax is based upon the general
     * syntax but flattens it, optimizing it for the single digital
     * signature/MAC case.  It flattens it by removing the "signatures"
     * member and instead placing those members defined for use in the
     * "signatures" array (the "protected", "header", and "signature"
     * members) in the top-level JSON object (at the same level as the
     * "payload" member).
     *
     * The "signatures" member MUST NOT be present when using this syntax.
     * Other than this syntax difference, JWS JSON Serialization objects
     * using the flattened syntax are processed identically to those using
     * the general syntax.
     *
     * In summary, the syntax of a JWS using the flattened JWS JSON
     * Serialization is as follows:
     *
     * {@code
     *     {
     *      "payload":"<payload contents>",
     *      "protected":"<integrity-protected header contents>",
     *      "header":<non-integrity-protected header contents>,
     *      "signature":"<signature contents>"
     *     }
     * }
     */
    FLATTENED_JSON_SERIALIZATION;

}
