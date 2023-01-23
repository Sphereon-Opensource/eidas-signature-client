/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.sphereon.vdx.pkcs7.support

import org.apache.pdfbox.io.IOUtils
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSTypedData
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * Wraps a InputStream into a CMSProcessable object for bouncy castle. It's a memory saving alternative to the [ ] class.
 *
 * @author Thomas Chojecki
 */
class CMSProcessableInputStream internal constructor(private val contentType: ASN1ObjectIdentifier, private val `in`: InputStream) : CMSTypedData {
    constructor(`is`: InputStream) : this(ASN1ObjectIdentifier(CMSObjectIdentifiers.data.id), `is`)

    override fun getContent(): Any {
        return `in`
    }

    @Throws(IOException::class, CMSException::class)
    override fun write(out: OutputStream) {
        // read the content only one time
        IOUtils.copy(`in`, out)
        `in`.close()
    }

    override fun getContentType(): ASN1ObjectIdentifier {
        return contentType
    }
}
