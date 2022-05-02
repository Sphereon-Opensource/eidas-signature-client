package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.model.CertificateProviderSettings
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.sign.util.ConnectionFactory
import com.sphereon.vdx.ades.sign.util.fromDSS
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection


class CertificateProviderService(override val settings: CertificateProviderSettings) : ICertificateProviderService {

    private val tokenConnection = ConnectionFactory.connection(settings)

    override fun getKeys(): List<IKeyEntry> {
        return tokenConnection.keys.map { it.fromDSS() }
    }

    override fun getKey(alias: String): IKeyEntry? {
        return when (tokenConnection) {
            is AbstractKeyStoreTokenConnection -> tokenConnection.getKey(alias)?.fromDSS(alias)
            else -> getKeys().first { it.alias == alias }
        }
    }
}
