<?php
/**
 * Produce a nested JWT token that is first signed and then encrypted.
 * Signature shall be computed using an elliptic curve cryptography.
 * Key management shall be done using AES-GCM key wrapping.
 * Content shall be encrypted using AES in CBC mode with SHA-2 based integrity
 * and authentication.
 *
 * php nested-create.php
 */

declare(strict_types = 1);

use Sop\CryptoEncoding\PEM;
use Sop\JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use Sop\JWX\JWE\KeyAlgorithm\A128GCMKWAlgorithm;
use Sop\JWX\JWK\EC\ECPrivateKeyJWK;
use Sop\JWX\JWS\Algorithm\ES256Algorithm;
use Sop\JWX\JWT\Claim\Claim;
use Sop\JWX\JWT\Claim\ExpirationTimeClaim;
use Sop\JWX\JWT\Claim\IssuerClaim;
use Sop\JWX\JWT\Claims;
use Sop\JWX\JWT\JWT;

require dirname(__DIR__) . '/vendor/autoload.php';

// load EC private key
$ec_priv_jwk = ECPrivateKeyJWK::fromPEM(
    PEM::fromFile(dirname(__DIR__) . '/test/assets/ec/private_key_P-256.pem'));
// initialize ES256 signature algorithm and set key ID
$sig_algo = ES256Algorithm::fromPrivateKey($ec_priv_jwk)->withKeyID('sig-key');
// initialize A128GCMKW key management algorithm and set key ID
$kek = '0123456789abcdef';
$key_algo = A128GCMKWAlgorithm::fromKey($kek)->withKeyID('enc-key');
// initialize A128CBC-HS256 content encryption algorithm
$enc_algo = new A128CBCHS256Algorithm();
// compose claims set
$claims = new Claims(
    new IssuerClaim('joe'),
    ExpirationTimeClaim::fromString('now + 1 hour'),
    new Claim('http://example.com/is_root', true));
// sign claims to produce JWT as a JWS
$jwt = JWT::signedFromClaims($claims, $sig_algo);
// encrypt JWS further to produce JWT as a JWE
$jwt = $jwt->encryptNested($key_algo, $enc_algo);
echo "{$jwt}\n";
