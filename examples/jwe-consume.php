<?php
/**
 * Decrypt an encrypted JWT token and print claims.
 * Private key is used for decryption.
 *
 * php jwe-consume.php $(php jwe-create.php)
 */

use CryptoUtil\PEM\PEM;
use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\KeyAlgorithm\RSAESPKCS1Algorithm;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\JWT\JWT;
use JWX\JWT\ValidationContext;

require dirname(__DIR__) . "/vendor/autoload.php";

// read JWT token from the first argument
$jwt = new JWT($argv[1]);
// load RSA private key
$jwk = RSAPrivateKeyJWK::fromPEM(
	PEM::fromFile(dirname(__DIR__) . "/test/assets/rsa/private_key.pem"));
$key_algo = RSAESPKCS1Algorithm::fromPrivateKey($jwk);
$enc_algo = new A128CBCHS256Algorithm();
$ctx = new ValidationContext();
// decrypt claims from the encrypted JWT
$claims = $jwt->claimsFromJWE($key_algo, $enc_algo, $ctx);
// print all claims
foreach ($claims as $claim) {
	echo $claim->name() . ": " . json_encode($claim->value()) . "\n";
}
