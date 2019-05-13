<?php
/**
 * Decrypt a JWE token to reclaim the payload.
 * JWE header contains all the necessary parameterization for decryption.
 * Password for the for key management shall be supplied using a JSON Web Key.
 *
 * php arbitrary-decrypt.php $(php arbitrary-encrypt.php)
 */

declare(strict_types = 1);

use Sop\JWX\JWE\JWE;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;

require dirname(__DIR__) . '/vendor/autoload.php';

// create a JSON Web Key from password
$jwk = SymmetricKeyJWK::fromKey('MySecretPassword');
// read JWE token from the first argument
$jwe = JWE::fromCompact($argv[1]);
// decrypt the payload using a JSON Web Key
$payload = $jwe->decryptWithJWK($jwk);
echo "{$payload}\n";
