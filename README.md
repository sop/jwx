[![Build Status](https://travis-ci.org/sop/jwx.svg?branch=master)](https://travis-ci.org/sop/jwx)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/sop/jwx/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/sop/jwx/?branch=master)
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

-   Signing and signature validation (JWS)
    -   HMAC, RSA and EC
-   Encryption and decryption with compression and integrity protection (JWE)
    -   AES
-   Claims validation
    -   Configurable with sensible defaults
-   JSON Web Keys (JWK)
    -   Convert PEM encoded keys to JWK and vice versa

## Supported algorithms

-   Signature
    -   HMAC with SHA-256, SHA-384 and SHA-512
    -   RSASSA-PKCS1-v1_5 with SHA-256, SHA-384 and SHA-512
    -   ECDSA with P-256, P-384 and P-521 curves
-   Content encryption
    -   AES-CBC with 128, 192 and 256-bit key sizes
    -   AES-GCM with 128, 192 and 256-bit key sizes
-   Key management
    -   Shared symmetric key (direct)
    -   RSAES-PKCS1-v1_5
    -   RSAES OAEP
    -   AES Key Wrap with 128, 192 and 256-bit key sizes
    -   AES-GCM key encryption with 128, 192 and 256-bit key sizes
    -   Password-based key encryption (PBES2 with AES Key Wrap)
-   Compression
    -   DEFLATE

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

### Simple JWT

Parse JWT from [https://jwt.io/](https://jwt.io/#debugger-io) example.

```php
$jwt = new JWT($token);
// create context for the claims validation
// "secret" key is used to verify the signature
$ctx = ValidationContext::fromJWK(
    SymmetricKeyJWK::fromKey("secret"));
// validate claims
$claims = $jwt->claims($ctx);
// print value of the subject claim
echo $claims->subject()->value() . "\n";
```

### Additional Validation

Parse the same token as above but additionally validate subject and admin claims.

```php
$jwt = new JWT($token);
// validate that the subject is "1234567890"
// validate that the admin claim is true using explicitly provided validator
$ctx = ValidationContext::fromJWK(
    SymmetricKeyJWK::fromKey("secret"),
    ["sub" => "1234567890"])->withConstraint(
        "admin", true, new EqualsValidator());
// validate and print all claims
$claims = $jwt->claims($ctx);
foreach ($claims as $claim) {
    printf("%s: %s\n", $claim->name(), $claim->value());
}
```

### More Examples

See [`/examples`](https://github.com/sop/jwx/tree/master/examples)
directory for more examples.

-   [Create a signed JWT](https://github.com/sop/jwx/blob/master/examples/jws-create.php)
-   [Consume a signed JWT](https://github.com/sop/jwx/blob/master/examples/jws-consume.php)
-   [Create an encrypted JWT](https://github.com/sop/jwx/blob/master/examples/jwe-create.php)
-   [Consume an encrypted JWT](https://github.com/sop/jwx/blob/master/examples/jwe-consume.php)
-   [Create a nested JWT](https://github.com/sop/jwx/blob/master/examples/nested-create.php)
-   [Consume a nested JWT](https://github.com/sop/jwx/blob/master/examples/nested-consume.php)
-   [Encrypt arbitrary data](https://github.com/sop/jwx/blob/master/examples/arbitrary-encrypt.php)
-   [Decrypt arbitrary data](https://github.com/sop/jwx/blob/master/examples/arbitrary-decrypt.php)

## License

This project is licensed under the MIT License.
