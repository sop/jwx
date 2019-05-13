<?php
/**
 * Produce a JWE token by encrypting arbitrary data.
 * Key management shall be done using password based key encryption.
 * The content shall be encrypted using AES-GCM with a 128-bit key.
 *
 * php arbitrary-encrypt.php
 */

declare(strict_types = 1);

use Sop\JWX\JWE\CompressionAlgorithm\DeflateAlgorithm;
use Sop\JWX\JWE\EncryptionAlgorithm\A128GCMAlgorithm;
use Sop\JWX\JWE\JWE;
use Sop\JWX\JWE\KeyAlgorithm\PBES2HS256A128KWAlgorithm;

require dirname(__DIR__) . '/vendor/autoload.php';

$payload = 'My hovercraft is full of eels.';
$password = 'MySecretPassword';

// PBES2-HS256+A128KW as a key management algorithm with default parameters
$key_algo = PBES2HS256A128KWAlgorithm::fromPassword($password);
// A128GCM as an encryption algorithm
$enc_algo = new A128GCMAlgorithm();
// DEF as a compression algorithm
$zip_algo = new DeflateAlgorithm();
// encrypt payload to produce JWE
$jwe = JWE::encrypt($payload, $key_algo, $enc_algo, $zip_algo);
// JWE's __toString magic method generates compact serialization
echo "{$jwe}\n";
