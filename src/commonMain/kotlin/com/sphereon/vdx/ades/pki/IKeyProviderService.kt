package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.PKIException
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.KeyProviderSettings
import com.sphereon.vdx.ades.sign.ISimpleSignatureService

/**
 * The interface for the PKI service adds key functionality to the simple signature interface.
 */
interface IKeyProviderService : ISimpleSignatureService {

    /**
     * The Key Provider Settings
     */
    val settings: KeyProviderSettings

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
     * Retrieves a specific key by its kid.
     *
     * @param kid The key identifier
     * @return The key
     * @throws PKIException
     * If there is any problem during the retrieval process
     */
    @Throws(PKIException::class)
    fun getKey(kid: String): IKeyEntry?
}
