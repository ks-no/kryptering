# Kryptering
[![MIT Licens](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/ks-no/kryptering/blob/master/LICENSE)
[![Maven Central](https://img.shields.io/maven-central/v/no.ks.fiks/kryptering.svg)](https://search.maven.org/search?q=g:no.ks.fiks%20a:kryptering)
![GitHub Release Date](https://img.shields.io/github/release-date/ks-no/kryptering.svg)
![GitHub last commit](https://img.shields.io/github/last-commit/ks-no/kryptering.svg)

Java library for CMS (Cryptographic Message Syntax / PKCS#7) encryption and decryption,
used in the Fiks/KS ecosystem for secure data exchange. Data is encrypted with
**AES-256-CBC**, and the content key is wrapped with **RSA-OAEP** (SHA-256, MGF1) using
the recipient's X.509 certificate. The library wraps the [BouncyCastle](https://www.bouncycastle.org/)
CMS API and offers both a byte-array and a streaming variant.

## Installation

Requires Java 17. BouncyCastle is pulled in transitively. Add the dependency with Maven —
check the Maven Central badge above for the latest version:

```xml
<dependency>
    <groupId>no.ks.fiks</groupId>
    <artifactId>kryptering</artifactId>
    <version>2.4.0</version>
</dependency>
```

## API overview

`CMSKrypteringImpl` is the entry point and implements two interfaces:

- **`CMSArrayKryptering`** — in-memory `byte[]` encryption/decryption.
  `krypterData(byte[], X509Certificate)` and `dekrypterData(byte[], PrivateKey)`.
- **`CMSStreamKryptering`** — streaming encryption/decryption for large payloads without
  loading everything into memory, via `InputStream`/`OutputStream`
  (`krypterData(...)`, `dekrypterData(...)`, `getKrypteringOutputStream(...)`).

Encryption takes the recipient's `X509Certificate`; decryption takes the matching
`PrivateKey`. Each method has an overload accepting an explicit JCA `Provider`.
`KSKeyStoreLoader` is a helper for loading private keys and certificates from a keystore
(JCEKS by default).

```java
CMSKrypteringImpl kryptering = new CMSKrypteringImpl(); // reuse this instance, see note below

KSKeyStoreLoader keyStore = new KSKeyStoreLoader("keystore.jceks", "storePassword".toCharArray());
X509Certificate certificate = keyStore.getPublicKey("alias");       // recipient's public certificate
PrivateKey privateKey = keyStore.getPrivateKey("alias", "keyPassword".toCharArray());

byte[] encrypted = kryptering.krypterData("hello".getBytes(StandardCharsets.UTF_8), certificate);
byte[] decrypted = kryptering.dekrypterData(encrypted, privateKey); // -> "hello"
```

> **Note:** Constructing `CMSKrypteringImpl` registers the BouncyCastle security provider
> and is relatively expensive — reuse a single instance instead of creating one per call
> (see [JDK-8168469](https://bugs.openjdk.java.net/browse/JDK-8168469)).

## Building

```sh
mvn clean install
```

The library is covered by JUnit 5 unit tests; it has no component/integration tests, by
design.

## License

[MIT](LICENSE)
