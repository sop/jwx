<?php
/**
 * Decrypt an encrypted JWT token and print claims.
 * Private key is used for decryption.
 *
 * php jwe-consume.php $(php jwe-create.php)
 */

declare(strict_types = 1);

use Sop\CryptoEncoding\PEM;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\RSA\RSAPrivateKeyJWK;
use Sop\JWX\JWT\JWT;
use Sop\JWX\JWT\ValidationContext;

require dirname(__DIR__) . '/vendor/autoload.php';

// read JWT token from the first argument
$jwt = new JWT($argv[1]);
// load RSA private key
$jwk = RSAPrivateKeyJWK::fromPEM(
    PEM::fromFile(dirname(__DIR__) . '/test/assets/rsa/private_key.pem'));
// create validation context containing only key for decryption
$ctx = ValidationContext::fromJWK($jwk)
    // NOTE: asymmetric key derivation algorithms are not enabled by default
    // due to sign/encrypt confusion vulnerability!
    ->withPermittedAlgorithmsAdded(JWA::ALGO_RSA1_5);
// decrypt claims from the encrypted JWT
$claims = $jwt->claims($ctx);
// print all claims
foreach ($claims as $claim) {
    printf("%s: %s\n", $claim->name(), json_encode($claim->value()));
}
