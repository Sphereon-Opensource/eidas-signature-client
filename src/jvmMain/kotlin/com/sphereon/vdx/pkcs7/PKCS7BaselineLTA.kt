/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package com.sphereon.vdx.pkcs7

import eu.europa.esig.dss.model.DSSDocument
import eu.europa.esig.dss.model.DSSException
import eu.europa.esig.dss.pdf.IPdfObjFactory
import eu.europa.esig.dss.pdf.PDFSignatureService
import eu.europa.esig.dss.spi.x509.tsp.TSPSource
import eu.europa.esig.dss.validation.CertificateVerifier

/**
 * PAdES Baseline LTA signature
 */
internal class PKCS7BaselineLTA
/**
 * The default constructor
 *
 * @param tspSource [TSPSource] to use
 * @param certificateVerifier [CertificateVerifier]
 * @param pdfObjectFactory [IPdfObjFactory]
 */
    (tspSource: TSPSource?, certificateVerifier: CertificateVerifier?, pdfObjectFactory: IPdfObjFactory?) :
    PKCS7BaselineLT(tspSource, certificateVerifier, pdfObjectFactory) {
    @Throws(DSSException::class)
    override fun extendSignatures(document: DSSDocument, parameters: PKCS7SignatureParameters): DSSDocument {
        // check if needed to extend with PAdESLevelBaselineLT
        var document: DSSDocument? = document
        document = super.extendSignatures(document!!, parameters)

        // Will add a Document TimeStamp (not CMS)
        return timestampDocument(
            document, parameters.archiveTimestampParameters,
            parameters.passwordProtection, archiveTimestampService
        )
    }

    private val archiveTimestampService: PDFSignatureService
        /**
         * This method returns a `PDFSignatureService` to be used for an archive timestamp creation
         *
         * @return [PDFSignatureService]
         */
        private get() = pdfObjectFactory.newArchiveTimestampService()
}
