[![Build Status](https://travis-ci.org/sop/jwx.svg?branch=master)](https://travis-ci.org/sop/jwx)
[![Coverage Status](https://coveralls.io/repos/github/sop/jwx/badge.svg?branch=master)](https://coveralls.io/github/sop/jwx?branch=master)
[![License](https://poser.pugx.org/sop/jwx/license)](https://github.com/sop/jwx/blob/master/LICENSE)

# JWX
A PHP library for JSON web tokens
([JWT](https://tools.ietf.org/html/rfc7519))
with signature
([JWS](https://tools.ietf.org/html/rfc7515))
and encryption
([JWE](https://tools.ietf.org/html/rfc7516)) support.

Also implements unencoded payload option
([RFC 7797](https://tools.ietf.org/html/rfc7797)).

## Features
* Signing and signature validation (JWS)
    * HMAC and RSA
* Encryption and decryption with compression and integrity protection (JWE)
    * AES
* Claims validation
    * Configurable with sensible defaults
* JSON Web Keys (JWK)
    * Convert PEM encoded keys to JWK and vice versa

## Supported algorithms
* Signature
    * HMAC with SHA-256, SHA-384 and SHA-512
    * RSASSA-PKCS1-v1_5 with SHA-256, SHA-384 and SHA-512
* Content encryption
    * AES-CBC with 128, 192 and 256-bit key sizes
    * AES-GCM with 128, 192 and 256-bit key sizes
* Key management
    * Shared symmetric key (direct)
    * RSAES-PKCS1-v1_5
    * RSAES OAEP
    * AES Key Wrap with 128, 192 and 256-bit key sizes
    * AES-GCM key encryption with 128, 192 and 256-bit key sizes
    * Password-based key encryption (PBES2 with AES Key Wrap)
* Compression
    * DEFLATE

## Installation
This library is available on
[Packagist](https://packagist.org/packages/sop/jwx).

    composer require sop/jwx

## Usage
`Claims` class holds `Claim` objects that represent the claims.
The claims shall be encoded into a JWT which may further be
signed or encrypted, producing a JWS or a JWE respectively.

JWS and JWE may also be used to carry arbitrary payload, not just JSON claims.

## Code examples
Examples are located in
[`/examples`](https://github.com/sop/jwx/tree/master/examples)
directory.
* [Create a signed JWT](
    https://github.com/sop/jwx/blob/master/examples/jws-create.php)
* [Consume a signed JWT](
    https://github.com/sop/jwx/blob/master/examples/jws-consume.php)
* [Create an encrypted JWT](
    https://github.com/sop/jwx/blob/master/examples/jwe-create.php)
* [Consume an encrypted JWT](
    https://github.com/sop/jwx/blob/master/examples/jwe-consume.php)

## License
This project is licensed under the MIT License.
