@file:Suppress("MemberVisibilityCanBePrivate")

package com.sphereon.vdx.ades.pki

import com.mayakapps.kache.InMemoryKache
import com.mayakapps.kache.KacheStrategy
import com.mayakapps.kache.ObjectKache
import kotlinx.coroutines.runBlocking
import mu.KotlinLogging
import kotlin.time.DurationUnit
import kotlin.time.toDuration

private const val MAX_CACHE_SIZE = 1024L
private val logger = KotlinLogging.logger {}

open class CacheService<K : Any, V : Any>(
    private val cacheName: String,
    private val cacheEnabled: Boolean? = true,
    private val cacheTTLInSeconds: Long? = 600,
) {
    private var cache: ObjectKache<K, V>? = null

    init {
        initCache()
    }

    fun get(key: K): V? {
        return runBlocking {
            getAsync(key)
        }
    }

    suspend fun getAsync(key: K): V? {
        if (!isEnabled()) {
            return null
        }
        val value = cache!!.get(key)
        logger.debug { "Cache ${value?.let { "HIT" } ?: "MIS"} for key '$key' in cache '$cacheName'" }
        return value
    }

    fun isEnabled(): Boolean {
        return cacheEnabled == true && cache != null
    }

    fun put(key: K, value: V): V {
        return runBlocking {
            putAsync(key, value)
        }
    }

    suspend fun putAsync(key: K, value: V): V {
        logger.entry(key, value)
        if (isEnabled()) {
            logger.trace { "Caching value for key $key" }
            cache!!.put(key, value)
            if (cache!!.get(key) == null) {
                throw RuntimeException("Item was not placed in the cache")
            }
        }
        logger.exit(value)
        return value
    }

    private fun initCache() {
        logger.info { "Cache '$cacheName' is ${if (cacheEnabled == true) "" else "NOT"} being enabled..." }
        if (cacheEnabled == true) {
            if (cache == null) {
                cache = InMemoryKache(maxSize = MAX_CACHE_SIZE) {
                    strategy = KacheStrategy.LRU
                    expireAfterAccessDuration = cacheTTLInSeconds!!.toDuration(DurationUnit.SECONDS)
                }
                logger.info { "Cache '$cacheName' now is enabled" }
            }
        }
    }
}
