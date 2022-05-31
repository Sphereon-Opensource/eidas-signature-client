<!--suppress HtmlDeprecatedAttribute -->
<h1 align="center">
  <br>
  <a href="https://www.sphereon.com"><img src="https://sphereon.com/content/themes/sphereon/assets/img/logo.svg" alt="Sphereon" width="400"></a>
  <br>eIDAS Advanced Electronic Signature Client<br>
  <br>
</h1>

[![CI](https://github.com/Sphereon-Opensource/eidas-signature-client/actions/workflows/ci.yml/badge.svg)](https://github.com/Sphereon-Opensource/eidas-signature-client/actions/workflows/ci.yml)

The eIDAS Advanced Electronic Signature (AdES) client, allows to sign documents and digests (hashes), using CAdES (CMS, binary data), JAdES (JSON),
PAdES (PDF), XAdES (XML) signatures, as defined by the European Telecommunications Standards Institute (ETSI). These signatures are part of the eIDAS
legal framework in the European Union. Next to PAdES it can also create and verify PKCS#7 PDF signatures. These are non-ETSI, but are the more common
PDF signatures, provided by companies on Adobe's Approved Trust List.

The purpose of this client is to easily create and verify eIDAS and PKCS#7 compliant signatures for documents and input data, using certificates which
are stored
in keystore files (PKCS#12) or using hardware (PKCS#11). Documents can be signed by providing the full document or by generating a hash/digest of the
document first. Especially with remote signing REST APIs part of the Sphereon VDX platform, we suggest to create the digest first and then use the
signature to merge with the original document. This means you are not sending the full document across the wire, which obviously is better from a
privacy and security perspective.

# Table of Contents

- [Multiplatform library and REST API](#multiplatform-library-and-rest-api)
- [License](#license)
- [Signature flow](#signature-flow)
- [Certificate Provider Service](#certificate-provider-service)
    * [Initialize PKCS#12 Certificate Provider Service](#initialize-pkcs-12-certificate-provider-service)
        + [Use existing tooling to create a certificate and PKCS#12 keystore](#use-existing-tooling-to-create-a-certificate-and-pkcs-12-keystore)
            - [Creating a PKCS#12 keystore using OpenSSL](#creating-a-pkcs-12-keystore-using-openssl)
    * [Initialize Azure Keyvault or Managed HSM Certificate Provider Service](#initialize-azure-keyvault-or-managed-hsm-certificate-provider-service)
    * [List keys/certificates](#list-keys-certificates)
    * [Get a key/certificate by alias](#get-a-key-certificate-by-alias)
    * [Create the signature](#create-the-signature)
- [Signature Service](#signature-service)
    * [Initialize the Signature Service](#initialize-the-signature-service)
    * [Determine Sign Input](#determine-sign-input)
    * [Create a hash digest for additional privacy and security](#create-a-hash-digest-for-additional-privacy-and-security)
    * [Create the signature](#create-the-signature-1)
    * [Signing the original data, merging the signature](#signing-the-original-data--merging-the-signature)
    * [Check whether a signature is valid](#check-whether-a-signature-is-valid)
- [PDF Signatures](#pdf-signatures)
    * [Default PKCS#7 PDF signature](#default-pkcs-7-pdf-signature)
        + [PKCS#7 configuration options](#pkcs-7-configuration-options)
        + [Example PKCS#7 flow](#example-pkcs-7-flow)
- [Verifiable Credentials and SSI](#verifiable-credentials-and-ssi)
    + [Environment variables](#environment-variables)
- [Building and running the source code](#building-and-running-the-source-code)
    * [Requirements](#requirements)
    * [Adding as Maven dependency](#adding-as-maven-dependency)
    * [Gradle build (local maven repo)](#gradle-build--local-maven-repo-)

<small><i><a href='http://ecotrust-canada.github.io/markdown-toc/'>Table of contents generated with markdown-toc</a></i></small>

# Multiplatform library and REST API

This is a multiplatform Kotlin library. Right now it supports Java and Kotlin only. In the future Javascript/Typescript will be added. Please note
that
a REST API is also available that has integrated this client, allowing to generate and validate signatures using other languages. Next to Java/Kotlin,
Javascript/Typescript a .NET SDK is available that integrates with the REST API. SDK code can be generated for other languages based upon the OpenAPI
3 spec provided with the REST API.

# License

The signature client (this library) and most integrations are licensed as LGPLv3, meaning they can be integrated into commercial products without a
problem. Whenever changes are being made to the client or other libraries covered under this license and used by 3rd parties, the source-code
containing the changes has to be made available.

The REST API is licensed as GNU AGPLv3 as opposed to the libraries and SDKSs. GNU AGPLv3 means that the changed source-code must be made available for
parties interacting with the REST API.

Commercial clients paying a support fee or paying for on-premise products created by Sphereon get a perpetual commercial license for the particular
version(s) in use instead of the LGPLv3/GNU AGPLv3 licenses, which doesn't have the aforementioned source-code publication restrictions.

# Signature flow

Creating a signed AdES document comprises several steps. It starts with the Original Data/Document, for which we first need to determine the Sign
Input. The `SignInput` typically either is the full document, or a part of the document (PDF for instance). The `determineSignInput` method which
requires the input document together with the signature type and configuration as parameters, automatically determines the Sign Input. The
determineSignInput can be run locally without the need to use a REST API for instance.

Next there are two options. Directly signing the `SignInput` object using the `createSignature` method, resulting in a signature, or creating a
Digest (Hash) of the `SignInput`. Since the createSignature method could be using a remote REST service or remote Hardware Security Module for
instance, it is advisable to use the Digest method in most cases. The Digest method can be run locally, so even if the createSignature method needs to
access remote resources, no information from the original data/document would be sent across the wire. The digest method accepts a `SignInput` object
as
parameter and results in another `SignInput` object, with its sign method set to `DIGEST` instead of the original method of `DOCUMENT`.

The `createSignature` method accepts the `SignInput` object, which the signMode either being `DOCUMENT` or `DIGEST`, depending on which method was
chosen. It is using the supplied 'KeyEntry' or Key alias string to sign the input object. This can either be done locally or remotely depending on the
CertProvider implementation. The end result is a `Signature` object.

Lastly the `Signature` object needs to be merged with the original Document. It really depends on the type of signature being used how this is
achieved. The document could for instance become part of the signature (ENVELOPING), the signature could become part of the document (ENVELOPED), or
the signature could be detached (DETACHED)

The picture below gives a schematic overview of the process

![Signature Flow](./resources/ades%20signature%20flow.png)

It is possible to use multiple so called _SignatureServices_ with the same _CertificateProvider_. This allows for instance to extract bytes and create
a digest/hash
from the input file locally, while creating the signature using a REST API or Azure Keyvault for instance. Then the signature is recombined with the
original document locally. The
_createSignature_ method and its counterpart _verifySignature_ methods are typically ran using a REST API, Keyvault or locally with PKCS#11 hardware
Certificate Providers. It is up to the caller to determine whether creating the digest/hash, and placing the signature in the input document also
should run
remotely or not.

For non Kotlin/Java environments we advise to setup the eIDAS Signature REST Microservice on premise, which connects to PKCS#11 hardware, a QTSP or
Azure Keyvault remotely. Then use the REST endpoints, or use an SDK if available for your language. Please note that these SDKs typically have little
local processing functionality unlike the Kotlin/Java library. The setup ensures that Personally Identifiable Information (PII) or other sensitive
information doesn't leave your premise,
and that only the signature is being created remotely from the Digest/Hash value. It also allows you to use authentication and roles/authorization
locally on a per certificate and configuration level.

# Certificate Provider Service

The Certificate Provider Service allows to manage public/private keys and Certificates using either a PKCS#12 keystore file as byte array or filepath.
It also
has support for PKCS#11 hardware (HSM and USB cards) as well as support for a Remote REST Certificate Provider and a Azure Keyvault/Managed HSM
Certificate Provider. Next to certificate/key management a Certificate Provider also is responsible for creating and verifying signatures themselves.
Other operations, like creating a hash, merging a signature into an input document are handled by a Signature Service instead of the Certificate
Provider. A Single Certificate Provider can be shared by different Signature Services, as explained [above](#signature-flow)

Given the wide range of supported import/creation methods, this library does not create or
import certificates. Please use your method of choice (see [below](#use-existing-tooling-to-create-a-certificate-and-keystore) for some pointers).

## Initialize PKCS#12 Certificate Provider Service

The below example in Kotlin sets up a certificate service using a PKCS#12 keystore file at a certain path

````kotlin
val providerPath = "path/to/pkcs12.p12"
val passwordInputCallback = PasswordInputCallback(password = "password".toCharArray())
val providerConfig = CertificateProviderConfig(
    type = CertificateProviderType.PKCS12,
    pkcs12Parameters = KeystoreParameters(providerPath)
)
val certProvider = CertificateProviderService(
    CertificateProviderSettings(
        id = "my-pkcs12-provider",
        providerConfig,
        passwordInputCallback
    )
)
````

### Use existing tooling to create a certificate and PKCS#12 keystore

How to generate and/or import X.509 certificates and PKCS#12 keystores is out of scope of this project, but we provide some hints below. There are
numerous resources on the internet to create X.509 certificates and PKCS#12 keystores.

#### Creating a PKCS#12 keystore using OpenSSL

The private key and certificate must be in Privacy Enhanced Mail (PEM) format (for example, base64-encoded
with ``----BEGIN CERTIFICATE---- and ----END CERTIFICATE----`` headers and footers).

Use the following OpenSSL commands to create a PKCS#12 file from your private key and certificate. If you have one certificate, use the CA root
certificate.

````
openssl pkcs12 -export -in <signed_cert_filename> -inkey <private_key_filename> -name ‘tomcat’ -out keystore.p12
````

If you have a chain of certificates, combine the certificates into a single file and use it for the input file, as shown below. The order of
certificates must be from server certificate to the CA root certificate.

See RFC 2246 section 7.4.2 for more information about this order.

````
cat <signed_cert_filename> <intermediate.cert> [<intermediate2.cert>] > cert-chain.txt
openssl pkcs12 -export -in cert-chain.txt -inkey <private_key_filename> -name ‘tomcat’ -out keystore.p12
````

When prompted, provide a password for the new keystore.

## Initialize Azure Keyvault or Managed HSM Certificate Provider Service

The below example in Kotlin sets up a Certificate Service using Azure Keyvault or Azure Managed HSM. Both Keyvault and Managed HSM support Hardware
Security Modules. The Managed HSM service is Microsoft's solution for an HSM not shared with other customers/tenants.

**Note:** _Although the Azure Certificate Provider should work with Azure Managed HSM, the library is not being tested against Azure Managed HSM, as
opposed to Azure Keyvault._

````kotlin
val providerConfig = CertificateProviderConfig(
    type = CertificateProviderType.AZURE_KEYVAULT
)
val keyvaultConfig = AzureKeyvaultClientConfig(
    keyvaultUrl = "https://your-keyvault-here.vault.azure.net/",
    tenantId = "<your-directory-id-as-shown-in-keyvault-properties>",
    credentialOpts = CredentialOpts(
        credentialMode = CredentialMode.SERVICE_CLIENT_SECRET, // Use a client id and secret to authenticate as an app
        secretCredentialOpts = SecretCredentialOpts(
            clientId = "<client id which has access to keyvault>",
            clientSecret = "<client secret belonging to client id>"
        )
    ),
    hsmType = HSMType.KEYVAULT, // Either KEYVAULT as HSM (FIPS140 Level-2), or MANAGED_HSM
    applicationId = "your-application-id-or-name", // This can be randomly choosen
    exponentialBackoffRetryOpts = ExponentialBackoffRetryOpts(
        maxTries = 10, // let's try max 10 times
        baseDelayInMS = 500, // Wait 0,5 seconds the first time
        maxDelayInMS = 15000 // Wait for max 15 seconds eventually
    )
)

val providerSettings = CertificateProviderSettings(
    id = "my-keyvault-provider",
    providerConfig
)

// From a factory
var certProvider = CertificateProviderServiceFactory.createFromConfig(settings = providerSettings, azureKeyvaultClientConfig = keyvaultConfig)


// Or directly:
certProvider = AzureKeyvaultCertificateProviderService(providerSettings, keyvaultConfig)
````

## List keys/certificates

To list all available certificates of the provider one can use the getKeys() method. A list of IKeyEntry objects is being returned. The interface does
not expose private keys, as developers typically should not access the private key directly and not every supported implementation gives access to
private keys. If you are sure that key contains private keys, you can cas the result to IPrivateKeyEntry.

````kotlin
val keys = certProvider.getKeys()
println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(keys))
````

````json
[
  {
    "type": "PrivateKeyEntry",
    "alias": "test-key",
    "privateKey": {
      "algorithm": "RSA",
      "value": "MIIJRAIBAD....lpe53o2VXP",
      "format": "PKCS#8"
    },
    "encryptionAlgorithm": "RSA",
    "certificate": {
      "value": "MIIE...ybsgEkgc="
    },
    "certificateChain": [
      {
        "value": "MIIE...ybsgEkgc="
      }
    ]
  }
]
````

## Get a key/certificate by alias

Use the geKey(alias: String) method to get a single certificate IKeyEntry object by alias if it exists. If it does not exist null is being returned.
The IKeyEntry interface does not expose private keys, as developers typically should not access the private key directly and not every supported
implementation gives access to private keys. If you are sure that key contains private keys, you can cast the result to IPrivateKeyEntry. Make sure to
never sent private keys accoss unprotected network connections!

````kotlin
val key = certProvider.getKey("test-key")
println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(key))
````

````json
  {
  "type": "PrivateKeyEntry",
  "alias": "test-key",
  "privateKey": {
    "algorithm": "RSA",
    "value": "MIIJRAIBAD....lpe53o2VXP",
    "format": "PKCS#8"
  },
  "encryptionAlgorithm": "RSA",
  "certificate": {
    "value": "MIIE...ybsgEkgc="
  },
  "certificateChain": [
    {
      "value": "MIIE...ybsgEkgc="
    }
  ]
}
````

## Create the signature

Depending on the certificate provider this method could be traversing the network as it might call a signature REST API, or use a
network/cloud based Hardware Security Module containing the private key to sign. As such we advise to create the digest hash using a SignatureService
beforehand so original
documents/data is not being sent. Only the hash digest will traverse the network.

````kotlin
val signature = certProvider.createSignature(digestInput, keyEntry)
println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(signature))
````

````json lines
{
  // The actual signature
  "value": "SoSsp+Mut3....XEDqEVw==",
  "algorithm": "RSA_SHA256",
  "signMode": "DIGEST",
  // The certificate used during signing
  "certificate": {
    "value": "MIID1D....6Q42vNaS"
  },
  // The certificate chain including the Certificate Authority (CA) last
  "certificateChain": [
    {
      "value": "MIID1D....6Q42vNaS"
    },
    {
      "value": "MIID6j....GePoU8Ug=="
    },
    {
      "value": "MIIDVzC....PSNfsSBog=="
    }
  ]
}
````

# Signature Service

The Signature Service allows you to create and verify signatures, as well as creating a hash/digest of input data

## Initialize the Signature Service

The Signature service want to have a certificate provider as single argument. If you want to use multiple certificate providers you will have to
instantiate multiple signature services.

````kotlin
val signingService = SignatureService(certificateProvider = certProvider)
````

## Determine Sign Input

Determines the bytes that will serve as input for the `digest` or `createSignature` methods.
Since multiple signature types are supported the configuration and key are required te determine the appropriate mode of extraction. For instance
Pades signatures do not need a simple digest of the full file contents, depending on whether the PDF document already contains signatures. This method
should be called first when creating a signature.

````kotlin
val padesConfig = SignatureConfiguration(
    signatureParameters = SignatureParameters(
        // Make sure the signature becomes part of the file
        signaturePackaging = SignaturePackaging.ENVELOPED,
        // Use RSA and SHA256
        digestAlgorithm = DigestAlg.SHA256,
        encryptionAlgorithm = CryptoAlg.RSA,
        signatureLevelParameters = SignatureLevelParameters(
            // Set the level to PAdES baseline B
            signatureLevel = SignatureLevel.PAdES_BASELINE_B,
        ),
        signatureFormParameters = SignatureFormParameters(
            // PAdES specific parameters
            padesSignatureFormParameters = PadesSignatureFormParameters(
                signerName = "John Doe",
                contactInfo = "support@sphereon.com",
                reason = "Test",
                location = "Online"
            )
        )
    )
)

val pdfDoc = File("input.pdf")
val origData = OrigData(value = pdfDocInput.readBytes(), name = pdfDoc.name)
val keyEntry = signingService.certificateProvider.getKey("test-key")!!

val signInput = signingService.determineSignInput(
    origData = origData,
    keyEntry = keyEntry,
    signMode = SignMode.DOCUMENT,
    signatureConfiguration = signatureConfiguration
)
println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(signInput))
````

The below SignInput object could be used directly for the createSignature method or a digest can be created first, so that the input data will never
traverse a network if a remote Sign REST API or remote Hardware Security Module is being used.

````json lines
{
  "input": "MYHeMBgGCSqG....TAkxVAgEK",
  "signMode": "DOCUMENT",
  "digestAlgorithm": "SHA256",
  "name": "input.pdf"
}
````

## Create a hash digest for additional privacy and security

The `digest` method creates a hash digest out of the SignInput. The hash digest is a one way function that creates the fingerprint of the file. From
the digest you cannot get back to the original input data/document. This means any Personally Identifiable Data or Data which needs to stay private
will not be available to methods which need access to a remote REST API or remote Hardware Security Module. This obviously is preferable from a
privacy and security perspective. It allows users of the library to execute all methods on premise and then depending on the chosen Certificate
Provider sign the data either on premise or remotely. In no circumstance will the input data leave the premise.

````kotlin
val digestInput = signingService.digest(signInput)
println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(digestInput))
````

Notice that the below SignInput object is different from the passed in SignInput. The input value is shorter as it now is a hash digest. The signMode
moved from `DOCUMENT` to `DIGEST` so that the `createSignature` method knows not to create a hash digest out of the input anymore.

````json lines
{
  "input": "fSx6BzHxJ8p3Mn9E52DJ1eNrchfcMa1ZHaSjAi9D5z8=",
  "signMode": "DIGEST",
  "digestAlgorithm": "SHA256",
  "name": "input.pdf"
}
````

## Create the signature

The default Signature Service implementations delegate this method to the corresponding method of the CertificateProvider, given most
CertificateProviders to not expose private keys for security reasons.

Depending on the certificate provider settings this method could be traversing the network as it might call a signature REST API, or use a
network/cloud based Hardware Security Module containing the private key to sign. As such we advise to create the digest beforehand so original
documents/data is not being sent. Only the hash digest will traverse the network.

````kotlin
val signature = signingService.createSignature(digestInput, keyEntry)
println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(signature))
````

````json lines
{
  // The actual signature
  "value": "SoSsp+Mut3....XEDqEVw==",
  "algorithm": "RSA_SHA256",
  "signMode": "DIGEST",
  // The certificate used during signing
  "certificate": {
    "value": "MIID1D....6Q42vNaS"
  },
  // The certificate chain including the Certificate Authority (CA) last
  "certificateChain": [
    {
      "value": "MIID1D....6Q42vNaS"
    },
    {
      "value": "MIID6j....GePoU8Ug=="
    },
    {
      "value": "MIIDVzC....PSNfsSBog=="
    }
  ]
}
````

## Signing the original data, merging the signature

This method takes the original input document, the created signature and merges them together to provide a signed output document. It needs access to
the configuration to know how and where the signature should be merged with the document.

````kotlin
val signOutput = signingService.sign(origData, signature, signatureConfiguration)

// Write the signed bytes to a file
File("signed-output.pdf").writeBytes(signOutput.value)

println(Json { prettyPrint = true; serializersModule = serializers }.encodeToString(signOutput))
````

The result of the above is a new file which is the input PDF, but now signed.

````json lines
{
  // The signed data/document
  "value": "JVBERi0xLjYNJ....4cmVmCjc2NzUwCiUlRU9GCg==",
  "signMode": "DIGEST",
  "digestAlgorithm": "SHA256",
  "name": "input-pades-baseline-b.pdf",
  "mimeType": "application/pdf",
  "signature": {
    "value": "SoSsp+Mut3....XEDqEVw==",
    "algorithm": "RSA_SHA256",
    "signMode": "DIGEST",
    "certificate": {
      "value": "MIID1DCC....XxY1e6Q42vNaS"
    },
    "certificateChain": [
      {
        "value": "MIID1DCC....XxY1e6Q42vNaS"
      },
      {
        "value": "MIID6jCC....Y+TpJGePoU8Ug=="
      },
      {
        "value": "MIIDVzCCAj....PSNfsSBog=="
      }
    ]
  }
}
````

## Check whether a signature is valid

The default Signature Service implementations delegate this method to the corresponding method of the CertificateProvider.

In order to check whether a signature is valid the SignInput is needed. If a reference to that data is not available anymore the `determineSignInput`
and depending on whether a hash digest was create the `digest` method are needed to get back the SignInput object.

````kotlin
val valid = signingService.isValidSignature(digestInput, signature, signature.certificate!!)
// Returns a boolean
````

# PDF Signatures

This library supports electronically signing PDF documents, including approval and certify signatures as well as visual signatures. Supported PDF
signature types are:

- **adbe.pkcs7.detached**, which is the default PDF document signature as used by Adobe and the most common type of signature
- **ETSI.PAdES/ETSI.CAdES.detached**, which is ETSI/eIDAS compliant (needs special Certificates provided by Trust Service Providers!)

## Default PKCS#7 PDF signature

This is the default PDF Signature type, typically used with Certificates provided by an organization on the Adobe Approved Trusted List (AATL).

There are 2 types of signatures possible:

- CERTIFICATION
    - Can only be applied once to a PDF document!
    - It acts like a seal, which typically is organization or department wide.
    - A blue bar will appear with name of the signer, the company and the CA that issued the Certificate
    - Allows to protect the document for further modifications at several levels
    - Optionally showing an image of the signature. Clickable to show more information
- APPROVAL
    - Can be applied multiple times.
    - This is what typically is being used for people signing the document.
    - It is comparable to a user signing a paper based document.
    - The signature shows the name and additional information.
    - Optionally showing an image of the signature. Clickable to show more information

### PKCS#7 configuration options

The below options are part of a configuration, but can typically also be provided on every invocation. This allows to use the same certificate for
instance for signing by multiple people by changing the signerName and related properties.

````kotlin
class Pkcs7SignatureFormParameters(
    /**
     * The signature mode, according to the PDF spec. Either needs to be APPROVAL or CERTIFICATION.
     *
     * - CERTIFICATION can only be applied once to a PDF document. It acts like a seal, which typically is organization or department wide.
     * A blue bar will appear with name of the signer, the company and the CA that issued the Certificate
     * - APPROVAL can be applied multiple times. This is what typically is being used for people signing the document. It is comparable to a user signing a paper based document.
     * The signature shows the name and additional information. Optionally showing an image of the signature. Clickable to show more information
     */
    val mode: PdfSignatureMode? = PdfSignatureMode.APPROVAL,

    /**
     * This attribute allows to explicitly specify the SignerName (name for the entity signing).
     * The person or authority signing the document.
     */
    val signerName: String,


    /** The signature creation reason  */
    val reason: String? = null,

    /** The contact info  */
    val contactInfo: String? = null,

    /** The signer's location  */
    val location: String? = null,

    /**
     * Defines the preserved space for a signature context. Only change if you know what you are doing
     *
     * Default : 9472 (default value in pdfbox)
     */
    val signatureSize: Int? = 9472,

    /**
     * This attribute allows to override the used Filter for a Signature.
     *
     * Default value is Adobe.PPKLite
     */
    val signatureFilter: String? = PdfSignatureFilter.ADOBE_PPKLITE.specName,

    /**
     * This attribute allows to override the used subFilter for a Signature.
     *
     * Default value is adbe.pkcs7.detached
     */
    val signatureSubFilter: String? = PdfSignatureSubFilter.ADBE_PKCS7_DETACHED.specName,

    /**
     * This attribute is used to create visible signature
     */
    val signatureImageParameters: SignatureImageParameters? = null,

    /**
     * This attribute allows to set permissions in case of a "certification signature". That allows to protect for
     * future change(s).
     */
    val permission: CertificationPermission? = null,

    /**
     * Password used to encrypt a PDF
     */
    val passwordProtection: String? = null
)
````

### Example PKCS#7 flow

Below an example is provided where a local Signing Service and a Local Azure Keyvault Certificate Provider is being used to sign with a certificate on
the AATL list, resulting in "blue-bar" signatures. The example key vault settings can be
found [above](#initialize-azure-keyvault-or-managed-hsm-certificate-provider-service). The createSignature/verifySignature/getCert(s) methods would
use the Azure Keyvault REST API, so we will be creating a digest first to ensure we are not sending the document to Azure Keyvault.

````kotlin
// Gets the file and set the orig data object
val pdfDocInput = this::class.java.classLoader.getResource("example-unsigned.pdf")
val origData = OrigData(value = pdfDocInput.readBytes(), name = "example-unsigned.pdf")


val certProvider = CertificateProviderServiceFactory.createFromConfig(
    settings = providerSettings, // See above for examples
    azureKeyvaultClientConfig = keyvaultConfig // See example above
)
// The factory has returned an Azure Keyvault Certificate Provider at this point

// Create a local signature service, which uses alias/strings to denote the certificates to use
val signingService = AliasSignatureService(certProvider)

val alias = "example:3f98a9a740fb41b79e3679cce7a34ba6" // The alias is Azure Keyvault certificate specific and is <certificate Id>:<version>

val signatureConfiguration = SignatureConfiguration(
    signatureParameters = SignatureParameters(
        signaturePackaging = SignaturePackaging.ENVELOPED,
        digestAlgorithm = DigestAlg.SHA256,
        encryptionAlgorithm = CryptoAlg.RSA,
        signatureAlgorithm = SignatureAlg.RSA_SHA256,
        signatureLevelParameters = SignatureLevelParameters(
            signatureLevel = SignatureLevel.PKCS7_B, // This sets the mode to PDF PKCS#7 (Basic signature)
        ),
        signatureFormParameters = SignatureFormParameters(
            // PKCS#7 specific parameters
            pkcs7SignatureFormParameters = Pkcs7SignatureFormParameters(
                mode = PdfSignatureMode.APPROVAL,   // Use an approval signature
                signerName = "Example User",
                contactInfo = "example@sphereon.com",
                reason = "Example",
                location = "Amsterdam",
            )
        )
    )
)

// Locally extract the bytes to be signed from the PDF document
val signInput = signingService.determineSignInput(
    origData = origData,
    alias = alias,
    signMode = SignMode.DOCUMENT,
    signatureConfiguration = signatureConfiguration
)

// Locally create a hash/digest of the extracted bytes
val digestInput = signingService.digest(signInput)

// Calls Azure Keyvault using the hash/digest and the certificate associated with the alias value
val signature = signingService.createSignature(digestInput, alias)

// Locally combine the original document with the created signature
val signOutput = signingService.sign(origData, signature, signatureConfiguration)

````

# Verifiable Credentials and SSI

This library can be used as part of a Self Sovereign Identity solution to sign [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/). For
more information we refer to the accompanying [SSI Proof Client](https://github.com/Sphereon-OpenSource/ssi-proof-client)

### Environment variables

Currently NA

# Building and running the source code

## Requirements

This library has the following minimal requirements:

Java 11 and higher (tested up to Java 17) for the build is required. At runtime Kotlin and Java can be used currently

Gradle 7.X and higher;

We strongly recommend using the latest available version of JDK, in order to have the most recent security fixes and cryptographical algorithm
updates.
Before processing the integration steps, please ensure you have successfully installed Maven and JVM with a required version.

## Adding as Maven dependency

The simplest way to include DSS to your Maven project is to add a repository into the pom.xml file in the root directory of your project as following:

````xml

<repositories>

  .....

  <repository>
    <id>sphereon-public</id>
    <name>Sphereon Public</name>
    <url>https://nexus.qa.sphereon.com/repository/sphereon-public/</url>
  </repository>
</repositories>

<dependencies>

....

<dependency>
  <groupId>com.sphereon.vdx</groupId>
  <artifactId>eidas-signature-client-jvm</artifactId> <!-- The Java implementation if this library -->
  <version>0.1.0</version>
</dependency>
</dependencies>
````

## Gradle build (local maven repo)

	gradlew clean deployToMavenLocal
