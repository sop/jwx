[![Build Status](https://travis-ci.org/sop/jwx.svg?branch=master)](https://travis-ci.org/sop/jwx)

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
    * AES-CBC with 128, 192 and 256 bit key sizes
* Key management
    * Shared symmetric key (direct)
    * RSAES-PKCS1-v1_5
    * RSAES OAEP
    * AES Key Wrap with 128, 192 and 256 bit key sizes
    * Password-based encryption (PBES2 with AES Key Wrap)
* Compression
    * DEFLATE

## Installation
This library is available on
[Packagist](https://packagist.org/packages/sop/jwx).

    composer require sop/jwx

## Usage
`Claims` class holds `Claim` objects that represent the claims. Claims shall be encoded into JWT that may further be signed or encrypted, producing JWS or JWE respectively.

## Code examples
Here are some simple usage examples. Namespaces are omitted for brevity.

### Create signed token
Compose JWT claims and produce a token signed with HMAC using SHA-256.

```php
$claims = new Claims(
    new IssuerClaim("John Doe"),
    new SubjectClaim("Jane Doe"),
    new AudienceClaim("acme-client"),
    IssuedAtClaim::now(),
    NotBeforeClaim::now(),
    ExpirationTimeClaim::fromString("now + 30 minutes"),
    new JWTIDClaim(UUIDv4::createRandom()),
    new Claim("custom claim", ["any", "values"])
);
$jwt = JWT::signedFromClaims($claims,
    new HS256Algorithm("secret"));
echo $jwt->token();
```

Outputs (truncated):

    eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJKb2huIERv***.Sm6Jz6SMLT6kCy01Ag84***

### Consume signed token
Validate signature and claims of the JWS token created above
and display *JWT ID* claim.

```php
$jwt = new JWT($token);
$ctx = (new ValidationContext())
    ->withIssuer("John Doe")
    ->withSubject("Jane Doe")
    ->withAudience("acme-client");
$claims = $jwt->claimsFromJWS(
    new HS256Algorithm("secret"), $ctx);
echo $claims->get(RegisteredClaim::NAME_JWT_ID)->value();
```

Outputs:

    d9b9f019-5ccf-4a7b-aa13-c20e83d9be43

### Create encrypted token
Produce a token encrypted with AES-128 in CBC mode and authenticated
using HMAC with SHA-256.
Key management shall be done with RSAES-PKCS1-v1_5.
Public key is used at the sender's end to encrypt CEK.
The claims are same as in previous example.

```php
$jwk = RSAPublicKeyJWK::fromPEM(
	PEM::fromFile("path/to/public_key.pem"));
$key_algo = RSAESPKCS1Algorithm::fromPublicKey($jwk);
$enc_algo = new A128CBCHS256Algorithm();
$cek = $enc_algo->generateRandomCEK();
$jwt = JWT::encryptedFromClaims(
    $claims, $cek, $key_algo, $enc_algo);
echo $jwt->token();
```

Outputs (truncated):

    eyJhbGciOi***.UaYBykrPwy***.kZ4i3uBqli***.Lk-mDXks-k***.LQPofSXAzC***

### Decrypt token
Decrypt JWE token created above and print *custom claim* value.
CEK is derived by decrypting encrypted key with private key.
The validation context `$ctx` is same as in signing example.

```php
$jwt = new JWT($token);
$jwk = RSAPrivateKeyJWK::fromPEM(
    PEM::fromFile("path/to/private_key.pem"));
$key_algo = RSAESPKCS1Algorithm::fromPrivateKey($jwk);
$enc_algo = new A128CBCHS256Algorithm();
$claims = $jwt->claimsFromJWE($key_algo, $enc_algo, $ctx);
print_r($claims->get("custom claim")->value());
```

Outputs:

```
Array
(
    [0] => any
    [1] => values
)
```

## License
This project is licensed under the MIT License.
