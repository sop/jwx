<?php
/**
 * Produce a JWT token encrypted with AES-128 in CBC mode and authenticated
 * using HMAC with SHA-256.
 * Key management shall be done with RSAES-PKCS1-v1_5.
 * Public key is used to encrypt the content.
 *
 * php jwe-create.php
 */

use CryptoUtil\PEM\PEM;
use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\KeyAlgorithm\RSAESPKCS1Algorithm;
use JWX\JWK\RSA\RSAPublicKeyJWK;
use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\ExpirationTimeClaim;
use JWX\JWT\Claim\IssuedAtClaim;
use JWX\JWT\Claim\NotBeforeClaim;
use JWX\JWT\Claims;
use JWX\JWT\JWT;

require dirname(__DIR__) . "/vendor/autoload.php";

// compose claims set
$claims = new Claims(new Claim("secret data", "for your eyes only"), 
	IssuedAtClaim::now(), NotBeforeClaim::now(), 
	ExpirationTimeClaim::fromString("now + 30 minutes"));
// load RSA public key
$jwk = RSAPublicKeyJWK::fromPEM(
	PEM::fromFile(dirname(__DIR__) . "/test/assets/rsa/public_key.pem"));
$key_algo = RSAESPKCS1Algorithm::fromPublicKey($jwk);
$enc_algo = new A128CBCHS256Algorithm();
// create an encrypted JWT token
$jwt = JWT::encryptedFromClaims($claims, $key_algo, $enc_algo);
echo $jwt->token() . "\n";
