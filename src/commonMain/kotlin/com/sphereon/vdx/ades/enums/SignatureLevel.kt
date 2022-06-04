package com.sphereon.vdx.ades.enums

import com.sphereon.vdx.ades.enums.SignatureForm.CAdES
import com.sphereon.vdx.ades.enums.SignatureForm.JAdES
import com.sphereon.vdx.ades.enums.SignatureForm.PAdES
import com.sphereon.vdx.ades.enums.SignatureForm.PKCS7

@kotlinx.serialization.Serializable
enum class SignatureLevel(val form: SignatureForm) {
//    XML_NOT_ETSI, XAdES_BES, XAdES_EPES, XAdES_T, XAdES_LT, XAdES_C, XAdES_X, XAdES_XL, XAdES_A, XAdES_BASELINE_B, XAdES_BASELINE_T, XAdES_BASELINE_LT, XAdES_BASELINE_LTA,

    CMS_NOT_ETSI(CAdES),
    CAdES_BES(CAdES), CAdES_EPES(CAdES), CAdES_T(CAdES), CAdES_LT(CAdES), CAdES_C(CAdES), CAdES_X(CAdES), CAdES_XL(CAdES),
    CAdES_A(CAdES), CAdES_BASELINE_B(CAdES), CAdES_BASELINE_T(CAdES), CAdES_BASELINE_LT(CAdES), CAdES_BASELINE_LTA(CAdES),

    PDF_NOT_ETSI(PKCS7), PKCS7_B(PKCS7), PKCS7_T(PKCS7), PKCS7_LT(PKCS7), PKCS7_LTA(PKCS7),
    PAdES_BASELINE_B(PAdES), PAdES_BASELINE_T(PAdES), PAdES_BASELINE_LT(PAdES), PAdES_BASELINE_LTA(PAdES),

    JSON_NOT_ETSI(JAdES), JAdES_BASELINE_B(JAdES), JAdES_BASELINE_T(JAdES), JAdES_BASELINE_LT(JAdES), JAdES_BASELINE_LTA(JAdES);

}
