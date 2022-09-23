package com.sphereon.vdx.ades.model

/**
 * Allows to bind a Key identifier, signature Config Id and a Key provider Id. Typically used in requests/responses.
 */
@kotlinx.serialization.Serializable
data class ConfigKeyBinding(
    /**
     * The Key identifier.
     */
    val kid: String,

    /**
     * The signature Config Id.
     */
    val signatureConfigId: String? = null,

    /**
     * The Key provider Id.
     */
    val keyProviderId: String
)
