[![Build Status](https://travis-ci.org/etcimon/botan.svg?branch=master)](https://travis-ci.org/etcimon/botan)


Botan Crypto Library
====================

Botan is a very complete crypto powerhouse packaged in a D library.

It is a translation of the C++ library [Botan](http://botan.randombit.net/), although the code is now in D and uses the [memutils](https://github.com/etcimon/memutils) library as a replacement for the C++ STL.

A TLS client/server with ALPN, SNI and HTTP/2 has been added to the [http2-botan vibe.d port](https://github.com/etcimon/vibe.0).

Getting Started
---------------

Botan has been tested on Windows x86, Windows x64, OSX x64, Linux x86, Linux x64 with DMD v2.099.1+ and LDC v1.31.0+

- Install [DMD](http://dlang.org/download) v2.099.1+

- Compile Botan tests using `dub test --arch=x86_64` for x64, or `dub test --arch=x86_mscoff` for x86.

Learning
--------

For further information, start with the [GitHub Wiki](https://github.com/etcimon/botan/wiki) for information on how to use this library.

You can read the API documentation in the [GitHub Pages](http://etcimon.github.io/botan)

Supported Algorithms
--------------------

Botan supports a range of cryptographic algorithms and protocols,
including:

### TLS/Public Key Infrastructure

  * SSL/TLS (from SSL v3 to TLS v1.2), including using preshared
    keys (TLS-PSK) or passwords (TLS-SRP)
  * X.509 certificates (including generating new self-signed and CA
    certs) and CRLs
  * Certificate path validation and OCSP
  * PKCS #10 certificate requests (creation and certificate issue)

### Public Key Cryptography

  * Encryption algorithms RSA, ElGamal, DLIES
    (padding schemes OAEP or PKCS #1 v1.5)
  * Signature algorithms RSA, DSA, ECDSA, GOST 34.10-2001, Nyberg-Rueppel,
    Rabin-Williams (padding schemes PSS, PKCS #1 v1.5, X9.31)
  * Key agreement techniques Diffie-Hellman and ECDH

### Block ciphers

  * Authenticated cipher modes EAX, OCB, GCM, SIV, and CCM
  * Unauthenticated cipher modes CTR, CBC, XTS, CFB, OFB, and ECB
  * AES (including constant time SSSE3 and AES-NI versions)
  * AES candidates Serpent, Twofish, MARS, CAST-256, RC6
  * DES, 3DES and DESX
  * National/telecom block ciphers SEED, KASUMI, MISTY1, GOST 28147
  * Other block ciphers including Threefish-512, Blowfish, CAST-128, IDEA,
    Noekeon, TEA, XTEA, RC2, RC5, SAFER-SK
  * Large block cipher construction Lion

### Stream Ciphers

  * RC4
  * Salsa20/XSalsa20
  * ChaCha20

### Hash functions

  * SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512
  * RIPEMD-160, RIPEMD-128, Tiger, Whirlpool
  * SHA-3 winner Keccak-1600
  * SHA-3 candidate Skein-512
  * Hash function combiners (Parallel and Comb4P)
  * National standard hashes HAS-160 and GOST 34.11
  * Obsolete or insecure hashes MD5, MD4, MD2
  * Non-cryptographic checksums Adler32, CRC24, CRC32

### Authentication Codes

  * HMAC
  * CMAC (aka OMAC1)
  * Obsolete designs CBC-MAC, ANSI X9.19 DES-MAC, and the
    protocol-specific SSLv3 authentication code

### Other Useful Things

  * Key derivation functions for passwords, including PBKDF2
  * Password hashing functions, including bcrypt
  * General key derivation functions KDF1 and KDF2 from IEEE 1363
  * PRFs from ANSI X9.42, SSL v3.0, TLS v1.0

### Recommended Algorithms

This section is by no means the last word on selecting which algorithms to
use.  However, botan includes a sometimes bewildering array of possible
algorithms, and unless you're familiar with the latest developments in the
field, it can be hard to know what is secure and what is not. The following
attributes of the algorithms were evaluated when making this list: security,
support by other implementations, patent/IP status, and efficiency (in
roughly that order).

If your data is in motion, strongly consider using TLS v1.2 as a pre built,
already standard and well studied protocol.

Otherwise, if you simply *must* do something custom, use:

* Message encryption: AES or Serpent in EAX or GCM mode

* General hash functions: SHA-256 or SHA-512

* Message authentication: HMAC with SHA-256

* Public Key Encryption: RSA, 2048+ bit keys, with OAEP and SHA-256
  ("EME1(SHA-256)")

* Public Key Signatures: RSA, 2048+ bit keys with PSS and SHA-512
  ("EMSA4(SHA-512)"), or ECDSA with SHA-256 or SHA-512

* Key Agreement: Diffie-Hellman or ECDH, with "KDF2(SHA-256)"

Issues
------

You can submit any issues in the github issue tracker. Any issue related to algorithms in the D library must also be
submitted to the corresponding [Botan C++ issue tracker](https://github.com/randombit/botan/issues).

TODO
----

- OCSP stapling

License
-------

Botan is released under the Simplified BSD License (see LICENSE.md for the specifics).
