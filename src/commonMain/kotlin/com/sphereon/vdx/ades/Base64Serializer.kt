package com.sphereon.vdx.ades

import io.matthewnelson.component.base64.decodeBase64ToArray
import io.matthewnelson.component.base64.encodeBase64
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object Base64Serializer : KSerializer<ByteArray> {

    override val descriptor = PrimitiveSerialDescriptor("Base64", kotlinx.serialization.descriptors.PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: ByteArray) {
        return encoder.encodeString(value.encodeBase64())
    }

    override fun deserialize(decoder: Decoder): ByteArray {
        val str = decoder.decodeString()
        return str.decodeBase64ToArray()!!
    }
}
