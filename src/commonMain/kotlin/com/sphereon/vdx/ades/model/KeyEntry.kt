package com.sphereon.vdx.ades.model

import com.sphereon.vdx.ades.Base64Serializer
import com.sphereon.vdx.ades.enums.CryptoAlg
import kotlinx.serialization.SerialName
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass

val serializers = SerializersModule {

    polymorphic(IKeyEntry::class) {
        subclass(PrivateKeyEntry::class)
        subclass(KeyEntry::class)
    }
}
val json = Json { serializersModule = serializers }

interface IKeyEntry {
    val attributes: Set<Attribute>?
    val kid: String
    val publicKey: Key
    val certificate: Certificate?
    val certificateChain: List<Certificate>?
    val encryptionAlgorithm: CryptoAlg
}

interface IPrivateKeyEntry : IKeyEntry {
    val privateKey: Key
}


@kotlinx.serialization.Serializable
@SerialName("KeyEntry")
data class KeyEntry(
    override val kid: String,
    override val publicKey: Key,
    override val attributes: Set<Attribute>? = null,
    override val encryptionAlgorithm: CryptoAlg,
    override val certificate: Certificate? = null,
    override val certificateChain: List<Certificate>? = null
) : IKeyEntry {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as KeyEntry

        if (kid != other.kid) return false
        if (publicKey != other.publicKey) return false
        if (attributes != other.attributes) return false
        if (encryptionAlgorithm != other.encryptionAlgorithm) return false
        if (certificate != other.certificate) return false
        if (certificateChain != other.certificateChain) return false

        return true
    }

    override fun hashCode(): Int {
        var result = kid.hashCode()
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + (attributes?.hashCode() ?: 0)
        result = 31 * result + encryptionAlgorithm.hashCode()
        result = 31 * result + (certificate?.hashCode() ?: 0)
        result = 31 * result + (certificateChain?.hashCode() ?: 0)
        return result
    }
}

@kotlinx.serialization.Serializable
@SerialName("PrivateKeyEntry")
data class PrivateKeyEntry(
    override val kid: String,
    override val privateKey: Key,
    override val publicKey: Key,
    override val attributes: Set<Attribute>? = null,
    override val encryptionAlgorithm: CryptoAlg,
    override val certificate: Certificate? = null,
    override val certificateChain: List<Certificate>? = null
) : IPrivateKeyEntry {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as PrivateKeyEntry

        if (kid != other.kid) return false
        if (privateKey != other.privateKey) return false
        if (publicKey != other.publicKey) return false
        if (attributes != other.attributes) return false
        if (encryptionAlgorithm != other.encryptionAlgorithm) return false
        if (certificate != other.certificate) return false
        if (certificateChain != other.certificateChain) return false

        return true
    }

    override fun hashCode(): Int {
        var result = kid.hashCode()
        result = 31 * result + privateKey.hashCode()
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + (attributes?.hashCode() ?: 0)
        result = 31 * result + encryptionAlgorithm.hashCode()
        result = 31 * result + (certificate?.hashCode() ?: 0)
        result = 31 * result + (certificateChain?.hashCode() ?: 0)
        return result
    }
}


@kotlinx.serialization.Serializable
data class Key(
    val algorithm: CryptoAlg,
    @kotlinx.serialization.Serializable(with = Base64Serializer::class) val value: ByteArray,
    val format: String? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Key

        if (algorithm != other.algorithm) return false
        if (!value.contentEquals(other.value)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = algorithm.hashCode()
        result = 31 * result + value.contentHashCode()
        return result
    }
}

@kotlinx.serialization.Serializable
data class Attribute(val name: String, val value: String)

