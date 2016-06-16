<?php
/**
 * Decrypt an encrypted JWT token and print claims.
 * Private key is used for decryption.
 *
 * php jwe-consume.php $(php jwe-create.php)
 */

use CryptoUtil\PEM\PEM;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\JWT\JWT;
use JWX\JWT\ValidationContext;

require dirname(__DIR__) . "/vendor/autoload.php";

// read JWT token from the first argument
$jwt = new JWT($argv[1]);
// load RSA private key
$jwk = RSAPrivateKeyJWK::fromPEM(
	PEM::fromFile(dirname(__DIR__) . "/test/assets/rsa/private_key.pem"));
// create validation context containing only key for decryption
$ctx = ValidationContext::fromKey($jwk);
// decrypt claims from the encrypted JWT
$claims = $jwt->claims($ctx);
// print all claims
foreach ($claims as $claim) {
	echo $claim->name() . ": " . json_encode($claim->value()) . "\n";
}
