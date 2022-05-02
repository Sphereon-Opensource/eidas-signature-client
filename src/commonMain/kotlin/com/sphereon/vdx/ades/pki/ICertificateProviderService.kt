package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.model.CertificateProviderSettings
import com.sphereon.vdx.ades.model.IKeyEntry

interface ICertificateProviderService {

    val settings: CertificateProviderSettings

    /**
     * Retrieves all the available keys (private keys entries) from the token.
     *
     * @return List of encapsulated private keys
     * @throws PKIException
     * If there is any problem during the retrieval process
     */
    @Throws(PKIException::class)
    fun getKeys(): List<IKeyEntry>

    /**
     * Retrieves a specific key by its alias.
     *
     * @return The key
     * @throws PKIException
     * If there is any problem during the retrieval process
     */
    @Throws(PKIException::class)
    fun getKey(alias: String): IKeyEntry?
}
