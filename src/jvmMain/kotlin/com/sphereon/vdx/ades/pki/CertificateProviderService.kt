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


private const val CACHE_NAME = "keys"

class CertificateProviderService(override val settings: CertificateProviderSettings) : ICertificateProviderService {
    private val cacheEnabled = settings.config.cacheEnabled == true
    private var cache: Cache<String, IKeyEntry>? = null
    private val tokenConnection = ConnectionFactory.connection(settings)

    init {
        initCache()
    }


    override fun getKeys(): List<IKeyEntry> {
        return tokenConnection.keys.map { if (it is KSPrivateKeyEntry) it.fromDSS(it.alias) else it.fromDSS(it.certificate.toCertificate().fingerPrint) }
    }

    override fun getKey(alias: String): IKeyEntry? {
        return cacheGet(alias) ?: when (tokenConnection) {
            is AbstractKeyStoreTokenConnection -> {
                val key = tokenConnection.getKey(alias)?.fromDSS(alias)
                if (key != null && cache != null) {
                    cache!!.put(key.alias, key)
                }
                return key
            }
            else -> getKeys().first { it.alias == alias }
        }
    }

    private fun cacheGet(alias: String): IKeyEntry? {
        if (!cacheEnabled || cache == null) {
            return null
        }
        return cache!!.get(alias)
    }

    private fun initCache() {
        if (cacheEnabled) {
            val cachingProvider = Caching.getCachingProvider()
            val cacheManager = cachingProvider.cacheManager
            val config: MutableConfiguration<String, IKeyEntry> = MutableConfiguration()

            cache = cacheManager!!.getCache(CACHE_NAME)
            if (cache == null) {
                config.setExpiryPolicyFactory(AccessedExpiryPolicy.factoryOf(Duration(TimeUnit.SECONDS, settings.config.cacheTTLInSeconds ?: 30)))
                cache = cacheManager.createCache(CACHE_NAME, config)
            }
        }
    }
}
