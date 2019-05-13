<?php
/**
 * Compose JWT claims and produce a token signed with HMAC using SHA-256.
 *
 * php jws-create.php
 */

declare(strict_types = 1);

use Sop\JWX\JWS\Algorithm\HS256Algorithm;
use Sop\JWX\JWT\Claim\AudienceClaim;
use Sop\JWX\JWT\Claim\Claim;
use Sop\JWX\JWT\Claim\ExpirationTimeClaim;
use Sop\JWX\JWT\Claim\IssuedAtClaim;
use Sop\JWX\JWT\Claim\IssuerClaim;
use Sop\JWX\JWT\Claim\JWTIDClaim;
use Sop\JWX\JWT\Claim\NotBeforeClaim;
use Sop\JWX\JWT\Claim\SubjectClaim;
use Sop\JWX\JWT\Claims;
use Sop\JWX\JWT\JWT;
use Sop\JWX\Util\UUIDv4;

require dirname(__DIR__) . '/vendor/autoload.php';

// compose claims set
$claims = new Claims(
    new IssuerClaim('John Doe'),
    new SubjectClaim('Jane Doe'),
    new AudienceClaim('acme-client'),
    IssuedAtClaim::now(),
    NotBeforeClaim::now(),
    ExpirationTimeClaim::fromString('now + 30 minutes'),
    new JWTIDClaim(UUIDv4::createRandom()->canonical()),
    new Claim('custom claim', ['any', 'values']));
// create a signed JWT using HS256 with "secret" as a password
$jwt = JWT::signedFromClaims($claims, new HS256Algorithm('secret'));
echo $jwt->token() . "\n";
