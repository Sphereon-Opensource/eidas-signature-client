package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.model.CertificateProviderSettings
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.sign.util.ConnectionFactory
import com.sphereon.vdx.ades.sign.util.fromDSS
import com.sphereon.vdx.ades.sign.util.toCertificate
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection
import eu.europa.esig.dss.token.KSPrivateKeyEntry
import java.util.concurrent.TimeUnit
import javax.cache.Cache
import javax.cache.Caching
import javax.cache.configuration.MutableConfiguration
import javax.cache.expiry.AccessedExpiryPolicy
import javax.cache.expiry.Duration

class RemoteCertificateProviderService(override val settings: CertificateProviderSettings) : ICertificateProviderService {

    private val tokenConnection = ConnectionFactory.connection(settings)
    private val cacheService = CacheService(settings)

    override fun getKeys(): List<IKeyEntry> {
        return tokenConnection.keys.map { if (it is KSPrivateKeyEntry) it.fromDSS(it.alias) else it.fromDSS(it.certificate.toCertificate().fingerPrint) }
    }

    override fun getKey(alias: String): IKeyEntry? {
        return cacheService.get(alias) ?: when (tokenConnection) {
            is AbstractKeyStoreTokenConnection -> {
                val key = tokenConnection.getKey(alias)?.fromDSS(alias)
                if (key != null) {
                    cacheService.put(key)
                }
                return key
            }
            else -> getKeys().first { it.alias == alias }
        }
    }


}
