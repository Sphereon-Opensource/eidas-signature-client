package com.sphereon.vdx.ades

import io.matthewnelson.component.base64.decodeBase64ToArray
import io.matthewnelson.component.base64.encodeBase64
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Serializer that can be used in Kotlin's serialization support to convert byte arrays into base64 strings and vice versa.
 */
object Base64Serializer : KSerializer<ByteArray> {

    override val descriptor = PrimitiveSerialDescriptor("Base64", kotlinx.serialization.descriptors.PrimitiveKind.STRING)

    /**
     * Serializes the given byte array into a base64 string.
     */
    override fun serialize(encoder: Encoder, value: ByteArray) {
        return encoder.encodeString(value.encodeBase64())
    }

    /**
     * Deserializes the given base64 string into a byte array.
     */
    override fun deserialize(decoder: Decoder): ByteArray {
        val str = decoder.decodeString()
        return str.decodeBase64ToArray()!!
    }
}
