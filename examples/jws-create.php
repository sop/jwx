<?php
/**
 * Compose JWT claims and produce a token signed with HMAC using SHA-256.
 *
 * php jws-create.php
 */

use JWX\JWS\Algorithm\HS256Algorithm;
use JWX\JWT\Claims;
use JWX\JWT\JWT;
use JWX\JWT\Claim\AudienceClaim;
use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\ExpirationTimeClaim;
use JWX\JWT\Claim\IssuedAtClaim;
use JWX\JWT\Claim\IssuerClaim;
use JWX\JWT\Claim\JWTIDClaim;
use JWX\JWT\Claim\NotBeforeClaim;
use JWX\JWT\Claim\SubjectClaim;
use JWX\Util\UUIDv4;

require dirname(__DIR__) . "/vendor/autoload.php";

// compose claims set
$claims = new Claims(new IssuerClaim("John Doe"), new SubjectClaim("Jane Doe"),
    new AudienceClaim("acme-client"), IssuedAtClaim::now(), NotBeforeClaim::now(),
    ExpirationTimeClaim::fromString("now + 30 minutes"),
    new JWTIDClaim(UUIDv4::createRandom()),
    new Claim("custom claim", ["any", "values"]));
// create a signed JWT using HS256 with "secret" as a password
$jwt = JWT::signedFromClaims($claims, new HS256Algorithm("secret"));
echo $jwt->token() . "\n";
