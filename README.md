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
legal framework in the European Union.

The purpose of this client is to easily create and verify eIDAS compliant signatures for documents and input data, using certificates which are stored
in keystore files (PKCS#12) or using hardware (PKCS#11). Documents can be signed by providing the full document or by generating a hash/digest of the
document first. Especially with remote signing REST APIs part of the Sphereon VDX platform, we suggest to create the digest first and then use the
signature to merge with the original document. This means you are not sending the full document across the wire, which obviously is better from a
privacy and security perspective.

# Multiplatform library (Kotlin and Java for now)

This is a multiplatform Kotlin library. Right now it supports Java and Kotlin only. In the future Javascript/Typescript will be added. Please note
that
a REST API is also available that has integrated this client, allowing to generate and validate signatures using other languages. Next to Java/Kotlin,
Javascript/Typescript a .NET SDK is available that integrates with the REST API.

# Signature flow

Creating a signed AdES document comprises several steps. It starts with the Original Data/Document, for which we first need to determine the Sign
Input. The `SignInput` typically either is the full document, or a part of the document (PDF for instance). The `determineSignInput` method which
requires the input document together with the signature type and configuration as parameters, automatically determines the Sign Input. The
determineSignInput can be run locally without the need to use a REST API for instance.

Next there are two options. Directly signing the `SignInput` object using the `createSignature` method, resulting in a signature, or creating a
Digest (Hash) of the `SignInput`. Since the createSignature method could be using a remote REST service or remote Hardware Security Module for
instance, it is advices to use the Digest method in most cases. The Digest method can be run locally, so even if the createSignature method needs to
access remote resources, no information from the orig data/document would be sent across the wire. The digest method accepts a `SignInput` object as
parameter and results in another `SignInput` object, with its sign method set to `DIGEST` instead of the original method of `DOCUMENT`.

The `createSignature` method accepts the `SignInput` object, which the signMode either being `DOCUMENT` or `DIGEST`, depending on which method was
chosen. It is using the supplied 'KeyEntry' to sign the input object. This can either be done locally or remotely depending on the CertProvider
implementation. The end result is a `Signature` object.

Lastly the `Signature` object needs to be merged with the original Document. It really depends on the type of signature being used how this is
achieved. The document could for instance become part of the signature (ENVELOPING), the signature could become part of the document (ENVELOPED), or
the signature could be detached (DETACHED)

The picture below gives a schematic overview of the process

![Signature Flow](./resources/ades%20signature%20flow.png)

# Certificate Provider Service

The Certificate Provider Service allows to manage public/private keys and Certificates using either a PKCS#12 keystore file as byte array or filepath.
It also
has support for PKCS#11 hardware (HSM and USB cards). Given the wide range of supported import/creation methods, this library does not create or
import certificates. Please use your method of choice (see [below](#use-existing-tooling-to-create-a-certificate-and-keystore) for some pointers)

## Initialize Certificate Provider Service

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

### Use existing tooling to create a certificate and keystore

How to generate and/or import X.509 certificates and PKCS#12 keystores is out of scope of this project, but we provide some hints below. There are
numerous resources on the internet to create X.509 certificates and PKCS#12 keystores.

#### Creating a keystore using OpenSSL

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

## List certificates

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

## Get a certificate by alias

Use the geKey(alias: String) method to get a single certificate IKeyEntry object by alias if it exists. If it does not exist null is being returned.
The IKeyEntry interface does not expose private keys, as developers typically should not access the private key directly and not every supported
implementation gives access to private keys. If you are sure that key contains private keys, you can cas the result to IPrivateKeyEntry.

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

In order to check whether a signature is valid the SignInput is needed. If a reference to that data is not available anymore the `determineSignInput`
and depending on whethe a hash digest was create the `digest` method are needed to get back the SignInput object.

````kotlin
val valid = signingService.isValidSignature(digestInput, signature, signature.certificate!!)
// Returns a boolean
````

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
