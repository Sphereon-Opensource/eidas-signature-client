package com.sphereon.vdx.ades.sign

import com.sphereon.vdx.ades.SigningException
import com.sphereon.vdx.ades.enums.MaskGenFunction
import com.sphereon.vdx.ades.enums.SignatureAlg
import com.sphereon.vdx.ades.model.IKeyEntry
import com.sphereon.vdx.ades.model.Key
import com.sphereon.vdx.ades.model.SignInput
import com.sphereon.vdx.ades.model.Signature

interface ISimpleSignatureService {
    /**
     *
     * This method signs the `signInput` data with the digest `digestAlg` and
     * the given `keyEntry`.
     *
     * @param signInput
     * The data that need to be signed
     * @param keyEntry
     * The certificate to use
     * @return the signature value representation with the used algorithm and the binary value
     * @throws SigningException
     * If there is any problem during the signature process
     */
    @Throws(SigningException::class)
    fun createSignature(signInput: SignInput, keyEntry: IKeyEntry): Signature

    /**
     * This method signs the `signInput` data with the digest `digestAlg`, the mask `mgf` and
     * the given `keyEntry`.
     *
     * @param signInput
     * The data that need to be signed
     * @param mgf
     * the mask generation function
     * @param keyEntry
     * The certificate to use
     * @return the signature value representation with the used algorithm and the binary value
     * @throws SigningException
     * If there is any problem during the signature process
     */
    @Throws(SigningException::class)
    fun createSignature(
        signInput: SignInput,
        keyEntry: IKeyEntry,
        mgf: MaskGenFunction
    ): Signature

    /**
     * This method signs the `signInput` data with the provided Signature Algorithm and
     * the given `keyEntry`.
     *
     * @param signInput
     * The data that need to be signed
     * @param signatureAlgorithm
     * the Signature Algorithm
     * @param keyEntry
     * The certificate to use
     * @return the signature value representation with the used algorithm and the binary value
     * @throws SigningException
     * If there is any problem during the signature process
     */
    @Throws(SigningException::class)
    fun createSignature(
        signInput: SignInput,
        keyEntry: IKeyEntry,
        signatureAlgorithm: SignatureAlg
    ): Signature

    fun isValidSignature(signInput: SignInput, signature: Signature, publicKey: Key): Boolean


    fun isValidSignature(signInput: SignInput, signature: Signature, keyEntry: IKeyEntry): Boolean
}
