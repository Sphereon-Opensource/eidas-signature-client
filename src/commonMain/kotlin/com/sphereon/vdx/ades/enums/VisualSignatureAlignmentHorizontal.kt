package com.sphereon.vdx.ades.enums

/**
 * Visual signature horizontal position on the pdf page
 */
enum class VisualSignatureAlignmentHorizontal {
    /**
     * default, x-axis is the x-coordinate
     */
    NONE,

    /**
     * x-axis is left padding
     */
    LEFT,

    /**
     * x-axis automatically calculated
     */
    CENTER,

    /**
     * x-axis is right padding
     */
    RIGHT
}
