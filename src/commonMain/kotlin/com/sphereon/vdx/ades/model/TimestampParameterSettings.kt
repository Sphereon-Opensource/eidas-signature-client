package com.sphereon.vdx.ades.model

import com.sphereon.vdx.ades.enums.DigestAlg
import com.sphereon.vdx.ades.enums.TimestampContainerForm

const val EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#"

@kotlinx.serialization.Serializable
data class TimestampParameterSettings(
    val visualSignatureParameters: VisualSignatureParameters? = null,
    val timestampContainerForm: TimestampContainerForm? = TimestampContainerForm.PDF,
    val digestAlgorithm: DigestAlg = DigestAlg.SHA256,
    val canonicalizationMethod: String = EXCLUSIVE
)
