import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.cbor.Cbor
import java.nio.ByteBuffer
import java.util.*
import javax.cache.configuration.Configuration

@OptIn(ExperimentalSerializationApi::class)
abstract class AbstractCacheObjectSerializer<K, V>(private val serializer: KSerializer<V>) {

    fun serialize(obj: V?): ByteBuffer? {
        return if (obj == null) {
            null
        } else {
            val bytes = Cbor.encodeToByteArray(serializer, obj)
            ByteBuffer.wrap(bytes)
        }
    }

    fun equals(obj: V?, binary: ByteBuffer?): Boolean {
        return Objects.equals(obj, read(binary))
    }

    fun read(binary: ByteBuffer?): V? {
        if (binary == null) {
            return null
        }
        return Cbor.decodeFromByteArray(serializer, binary.array())
    }

    abstract fun cacheConfiguration(cacheTTLInSeconds: Long? = 30): Configuration<K, V>

}

