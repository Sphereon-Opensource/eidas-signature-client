package com.sphereon.vdx.ades.enums

enum class TimestampType(val order: Int, val coversSignature: Boolean) {

    /** CAdES: id-aa-ets-contentTimestamp */
    CONTENT_TIMESTAMP(0, false),

    /** XAdES: AllDataObjectsTimestamp */
    ALL_DATA_OBJECTS_TIMESTAMP(0, false),

    /** XAdES: IndividualDataObjectsTimeStamp */
    INDIVIDUAL_DATA_OBJECTS_TIMESTAMP(0, false),

    /** CAdES: id-aa-signatureTimeStampToken, XAdES: SignatureTimeStamp */
    SIGNATURE_TIMESTAMP(1, true),

    /** CAdES: id-aa-ets-certCRLTimestamp, XAdES: RefsOnlyTimeStamp */
    VALIDATION_DATA_REFSONLY_TIMESTAMP(2, false),

    /** CAdES: id-aa-ets-escTimeStamp, XAdES: SigAndRefsTimeStamp */
    VALIDATION_DATA_TIMESTAMP(2, true),

    /** PAdES-LTV "document timestamp" */
    DOCUMENT_TIMESTAMP(3, true),

    /** CAdES: id-aa-ets-archiveTimestamp, XAdES: ArchiveTimeStamp */
    ARCHIVE_TIMESTAMP(3, true);

}
