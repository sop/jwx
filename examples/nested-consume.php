<?php
/**
 * Decrypt and verify signature of the JWT created by nested-create.php.
 *
 * php nested-consume.php $(php nested-create.php)
 */

use JWX\JWK\JWKSet;
use JWX\JWK\EC\ECPublicKeyJWK;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWT\JWT;
use JWX\JWT\ValidationContext;
use JWX\JWT\Claim\RegisteredClaim;
use Sop\CryptoEncoding\PEM;

require dirname(__DIR__) . "/vendor/autoload.php";

// load EC public key
$ec_pub_jwk = ECPublicKeyJWK::fromPEM(
    PEM::fromFile(dirname(__DIR__) . "/test/assets/ec/public_key_P-256.pem"));
// initialize symmetric key for key management algorithm
$kek_jwk = SymmetricKeyJWK::fromKey("0123456789abcdef");
// compose JWK set with identified keys
$keys = new JWKSet($ec_pub_jwk->withKeyID("sig-key"),
    $kek_jwk->withKeyID("enc-key"));
// read JWT token from the first argument
$jwt = new JWT($argv[1]);
// initialize validation context
$ctx = new ValidationContext([RegisteredClaim::NAME_ISSUER => "joe"], $keys);
// decrypt, verify signature and validate claims
$claims = $jwt->claims($ctx);
// print claims
foreach ($claims as $claim) {
    printf("%s: %s\n", $claim->name(), $claim->value());
}
