import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.PrivateKeyEntry
import kotlinx.serialization.KSerializer
import org.ehcache.config.builders.CacheConfigurationBuilder
import org.ehcache.config.builders.ExpiryPolicyBuilder
import org.ehcache.config.builders.ResourcePoolsBuilder
import org.ehcache.config.units.MemoryUnit
import org.ehcache.jsr107.Eh107Configuration
import org.ehcache.spi.serialization.Serializer
import java.time.Duration
import javax.cache.configuration.Configuration


class KeyEntryCacheSerializer : Serializer<IKeyEntry>,
    AbstractCacheObjectSerializer<String, IKeyEntry>(serializer = PrivateKeyEntry.serializer() as KSerializer<IKeyEntry>) {
    override fun cacheConfiguration(cacheTTLInSeconds: Long?): Configuration<String, IKeyEntry> {
        return Eh107Configuration.fromEhcacheCacheConfiguration(
            CacheConfigurationBuilder.newCacheConfigurationBuilder(
                String::class.java, IKeyEntry::class.java, ResourcePoolsBuilder
                    .heap(10)
                    .offheap(5, MemoryUnit.MB)
            )
                .withExpiry(ExpiryPolicyBuilder.timeToLiveExpiration(Duration.ofSeconds(cacheTTLInSeconds ?: 30)))
                .withValueSerializer(this)

        )
    }
}
