package com.sphereon.vdx.ades.model

import com.sphereon.vdx.ades.Base64Serializer
import com.sphereon.vdx.ades.enums.CryptoAlg
import kotlinx.serialization.SerialName
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass

val serializers = SerializersModule {

    // Ensures we can do polymorphic serialization of the both Key and Private Key entries using the IKeyEntry interface
    polymorphic(IKeyEntry::class) {
        subclass(PrivateKeyEntry::class)
        subclass(KeyEntry::class)
    }
}
val json = Json { serializersModule = serializers }

/**
 * The Key Entry interface which is the base interface for all Key entries.
 */
interface IKeyEntry {
    val attributes: Set<Attribute>?
    val kid: String
    val publicKey: Key
    val certificate: Certificate?
    val certificateChain: List<Certificate>?
    val encryptionAlgorithm: CryptoAlg
}

/**
 * A Key entry with a private key.
 */
interface IPrivateKeyEntry : IKeyEntry {
    val privateKey: Key
}


/**
 * Implementation of the Key Entry interface for a public key and optional certificate.
 */
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

/**
 * Implementation of the Private Key Entry interface for a private/public keypair and optional certificate.
 *
 * Please note that it does not subclass the KeyEntry class, because these are Kotlin data classes (meaning no inheritance).
 * Always use the interfaces for arguments and return values!
 */
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

/**
 * A Key can represent a public or private key. Whether it is a public or private key is determined by the class/object using this class.
 */
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

