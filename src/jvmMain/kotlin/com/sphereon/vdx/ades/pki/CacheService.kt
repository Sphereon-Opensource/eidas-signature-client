package com.sphereon.vdx.ades.pki

import com.sphereon.vdx.ades.model.KeyProviderSettings
import com.sphereon.vdx.ades.model.IKeyEntry
import java.util.concurrent.TimeUnit
import javax.cache.Cache
import javax.cache.Caching
import javax.cache.configuration.MutableConfiguration
import javax.cache.expiry.AccessedExpiryPolicy
import javax.cache.expiry.Duration

private const val CACHE_NAME = "keys"

class CacheService(private val settings: KeyProviderSettings) {
    private val cacheEnabled = settings.config.cacheEnabled == true
    private var cache: Cache<String, IKeyEntry>? = null

    init {
        initCache()
    }


    fun get(kid: String): IKeyEntry? {
        if (!cacheEnabled || cache == null) {
            return null
        }
        return cache!!.get(kid)
    }

    fun isEnabled(): Boolean {
        return cacheEnabled && cache != null
    }

    fun put(key: IKeyEntry): IKeyEntry {
        if (isEnabled()) {
            cache!!.put(key.kid, key)
        }
        return key
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
