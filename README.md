# JWX
A PHP library for JSON web tokens (JWT) with signature (JWS)
and encryption (JWE) support.

## Features
* Signing and signature validation (JWS)
    * HMAC and RSA
* Encryption and decryption with integrity protection (JWE)
    * AES
* Claims validation
    * Configurable with sensible defaults
* JSON Web Keys (JWK)
    * Convert PEM encoded keys to JWK and vice versa

## Installation
This library is available on
[Packagist](https://packagist.org/packages/sop/jwx).

    composer require sop/jwx

## Usage
`Claims` class holds `Claim` objects that represent the claims. Claims shall be encoded into JWT that may further be signed or encrypted, producing JWS or JWE respectively.

## Code examples
Here are some simple usage examples. Namespaces are omitted for brevity.

### Create signed token
Compose JWT claims and produce token signed with HMAC using SHA-256.

```php
$claims = new Claims(
    new IssuerClaim("John Doe"),
    new SubjectClaim("Jane Doe"),
    new AudienceClaim("acme-client"),
    IssuedAtClaim::now(),
    NotBeforeClaim::now(),
    ExpirationTimeClaim::fromString("now + 30 minutes"),
    new JWTIDClaim(UUIDv4::createRandom())
);
$jwt = JWT::signedFromClaims($claims,
    new HS256Algorithm("secret"));
echo $jwt->token();
```

Outputs (truncated):

    eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJKb2huIERv***.Sm6Jz6SMLT6kCy01Ag84***

### Consume signed token
Validate signature and claims of the JWS token created above
and display JWT ID claim.

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

Outputs (random):

    d9b9f019-5ccf-4a7b-aa13-c20e83d9be43

## License
This project is licensed under the MIT License.
