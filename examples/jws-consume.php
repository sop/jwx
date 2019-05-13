<?php
/**
 * Validate the signature and claims of the JWT token and display claims.
 *
 * php jws-consume.php $(php jws-create.php)
 */

declare(strict_types = 1);

use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWT\JWT;
use Sop\JWX\JWT\ValidationContext;

require dirname(__DIR__) . '/vendor/autoload.php';

// read JWT token from the first argument
$jwt = new JWT($argv[1]);
// key to use for signature validation
$jwk = SymmetricKeyJWK::fromKey('secret');
// create validation context
$ctx = ValidationContext::fromJWK($jwk)
    ->withIssuer('John Doe')
    ->withSubject('Jane Doe')
    ->withAudience('acme-client');
// get claims set from the JWT. signature shall be verified and claims
// validated according to validation context.
$claims = $jwt->claims($ctx);
// print all claims
foreach ($claims as $claim) {
    printf("%s: %s\n", $claim->name(), json_encode($claim->value()));
}
