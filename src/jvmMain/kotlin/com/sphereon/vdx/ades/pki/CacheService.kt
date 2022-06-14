package com.sphereon.vdx.ades.pki

import AbstractCacheObjectSerializer
import mu.KotlinLogging
import java.util.concurrent.TimeUnit
import javax.cache.Cache
import javax.cache.Caching
import javax.cache.configuration.Configuration
import javax.cache.configuration.MutableConfiguration
import javax.cache.expiry.AccessedExpiryPolicy
import javax.cache.expiry.Duration

private val logger = KotlinLogging.logger {}

open class CacheService<K, V>(
    private val cacheName: String,
    private val cacheEnabled: Boolean? = true,
    private val cacheTTLInSeconds: Long? = 60,
    private val serializer: AbstractCacheObjectSerializer<K, V>?
) {
    private var cache: Cache<K, V>? = null


    init {
        initCache()
    }


    fun get(key: K): V? {
        if (!isEnabled()) {
            return null
        }
        val v = cache!!.get(key)
        logger.debug { "Cache ${v?.let { "HIT" } ?: "MIS"} for key '$key' in cache '$cacheName'" }
        return v
    }

    fun isEnabled(): Boolean {
        return cacheEnabled == true && cache != null
    }

    fun put(key: K, value: V): V {
        logger.entry(key, value)
        if (isEnabled()) {
            logger.trace { "Caching value for key $key" }
            cache!!.put(key, value)
        }
        logger.exit(value)
        return value
    }

    private fun initCache() {
        logger.info { "Cache '$cacheName' is ${if (cacheEnabled == true) "" else "NOT"} being enabled..." }
        if (cacheEnabled == true) {
            val cachingProvider = Caching.getCachingProvider()
            val cacheManager = cachingProvider.cacheManager

            if (cache == null) {
                if (cacheManager.cacheNames.contains(cacheName)) {
                    this.cache = cacheManager.getCache(cacheName)
                } else {
                    // We get the config from the serializer of any. Default to a mutable config. This might clutter the logs with warnings in case of Ehcache,
                    // as our Kotlin data classes are cross-platform and cannot implement Java's Serializable interface
                    val config: Configuration<K, V> = serializer?.cacheConfiguration(cacheTTLInSeconds)
                        ?: MutableConfiguration<K, V>().setExpiryPolicyFactory(
                            AccessedExpiryPolicy.factoryOf(
                                Duration(TimeUnit.SECONDS, cacheTTLInSeconds!!)
                            )
                        )

                    cache = cacheManager.createCache(cacheName, config)
                    logger.info { "Cache '$cacheName' now is enabled" }
                }
            }
        }
    }
}
