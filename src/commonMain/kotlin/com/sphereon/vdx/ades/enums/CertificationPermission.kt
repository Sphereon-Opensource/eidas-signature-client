package com.sphereon.vdx.ades.enums

enum class CertificationPermission(val code: Int) {


    /**
     * No changes to the document are permitted; any change to the document shall invalidate the signature.
     */
    NO_CHANGE_PERMITTED(1),

    /**
     * Permitted changes shall be filling in forms, instantiating page templates, and signing; other changes shall
     * invalidate the signature.
     */
    MINIMAL_CHANGES_PERMITTED(2),

    /**
     * Permitted changes are the same as for 2, as well as annotation creation, deletion, and modification; other
     * changes shall invalidate the signature.
     */
    CHANGES_PERMITTED(3);

}
