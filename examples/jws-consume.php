<?php
/**
 * Validate the signature and claims of the JWT token and display claims.
 *
 * php jws-consume.php $(php jws-create.php)
 */

use JWX\JWS\Algorithm\HS256Algorithm;
use JWX\JWT\JWT;
use JWX\JWT\ValidationContext;

require dirname(__DIR__) . "/vendor/autoload.php";

// read JWT token from the first argument
$jwt = new JWT($argv[1]);
// create validation context
$ctx = (new ValidationContext())->withIssuer("John Doe")
	->withSubject("Jane Doe")
	->withAudience("acme-client");
// get claims set from the JWT. signature shall be verified and claims
// validated according to validation context.
$claims = $jwt->claimsFromJWS(new HS256Algorithm("secret"), $ctx);
// print all claims
foreach ($claims as $claim) {
	echo $claim->name() . ": " . json_encode($claim->value()) . "\n";
}
