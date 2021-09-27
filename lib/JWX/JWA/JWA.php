<?php

declare(strict_types = 1);

namespace Sop\JWX\JWA;

use Sop\JWX\JWK\JWK;
use Sop\JWX\JWT\Header\Header;

/**
 * Container for the algorithm name contants.
 *
 * @see http://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
 * @see http://www.iana.org/assignments/jose/jose.xhtml#web-encryption-compression-algorithms
 */
abstract class JWA
{
    /**
     * HMAC using SHA-256.
     */
    public const ALGO_HS256 = 'HS256';

    /**
     * HMAC using SHA-384.
     */
    public const ALGO_HS384 = 'HS384';

    /**
     * HMAC using SHA-512.
     */
    public const ALGO_HS512 = 'HS512';

    /**
     * RSASSA-PKCS1-v1_5 using SHA-256.
     */
    public const ALGO_RS256 = 'RS256';

    /**
     * RSASSA-PKCS1-v1_5 using SHA-384.
     */
    public const ALGO_RS384 = 'RS384';

    /**
     * RSASSA-PKCS1-v1_5 using SHA-512.
     */
    public const ALGO_RS512 = 'RS512';

    /**
     * ECDSA using P-256 and SHA-256.
     */
    public const ALGO_ES256 = 'ES256';

    /**
     * ECDSA using P-384 and SHA-384.
     */
    public const ALGO_ES384 = 'ES384';

    /**
     * ECDSA using P-521 and SHA-512.
     */
    public const ALGO_ES512 = 'ES512';

    /**
     * RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
     */
    public const ALGO_PS256 = 'PS256';

    /**
     * RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
     */
    public const ALGO_PS384 = 'PS384';

    /**
     * RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
     */
    public const ALGO_PS512 = 'PS512';

    /**
     * No digital signature or MAC performed.
     */
    public const ALGO_NONE = 'none';

    /**
     * RSAES-PKCS1-v1_5.
     */
    public const ALGO_RSA1_5 = 'RSA1_5';

    /**
     * RSAES OAEP using default parameters.
     */
    public const ALGO_RSA_OAEP = 'RSA-OAEP';

    /**
     * RSAES OAEP using SHA-256 and MGF1 with SHA-256.
     */
    public const ALGO_RSA_OAEP256 = 'RSA-OAEP-256';

    /**
     * AES Key Wrap using 128-bit key.
     */
    public const ALGO_A128KW = 'A128KW';

    /**
     * AES Key Wrap using 192-bit key.
     */
    public const ALGO_A192KW = 'A192KW';

    /**
     * AES Key Wrap using 256-bit key.
     */
    public const ALGO_A256KW = 'A256KW';

    /**
     * Direct use of a shared symmetric key.
     */
    public const ALGO_DIR = 'dir';

    /**
     * ECDH-ES using Concat KDF.
     */
    public const ALGO_ECDH_ES = 'ECDH-ES';

    /**
     * ECDH-ES using Concat KDF and "A128KW" wrapping.
     */
    public const ALGO_ECDH_ES_A128KW = 'ECDH-ES+A128KW';

    /**
     * ECDH-ES using Concat KDF and "A192KW" wrapping.
     */
    public const ALGO_ECDH_ES_A192KW = 'ECDH-ES+A192KW';

    /**
     * ECDH-ES using Concat KDF and "A256KW" wrapping.
     */
    public const ALGO_ECDH_ES_A256KW = 'ECDH-ES+A256KW';

    /**
     * Key wrapping with AES GCM using 128-bit key.
     */
    public const ALGO_A128GCMKW = 'A128GCMKW';

    /**
     * Key wrapping with AES GCM using 192-bit key.
     */
    public const ALGO_A192GCMKW = 'A192GCMKW';

    /**
     * Key wrapping with AES GCM using 256-bit key.
     */
    public const ALGO_A256GCMKW = 'A256GCMKW';

    /**
     * PBES2 with HMAC SHA-256 and "A128KW" wrapping.
     */
    public const ALGO_PBES2_HS256_A128KW = 'PBES2-HS256+A128KW';

    /**
     * PBES2 with HMAC SHA-384 and "A192KW" wrapping.
     */
    public const ALGO_PBES2_HS384_A192KW = 'PBES2-HS384+A192KW';

    /**
     * PBES2 with HMAC SHA-512 and "A256KW" wrapping.
     */
    public const ALGO_PBES2_HS512_A256KW = 'PBES2-HS512+A256KW';

    /**
     * AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm.
     */
    public const ALGO_A128CBC_HS256 = 'A128CBC-HS256';

    /**
     * AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm.
     */
    public const ALGO_A192CBC_HS384 = 'A192CBC-HS384';

    /**
     * AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm.
     */
    public const ALGO_A256CBC_HS512 = 'A256CBC-HS512';

    /**
     * AES GCM using 128-bit key.
     */
    public const ALGO_A128GCM = 'A128GCM';

    /**
     * AES GCM using 192-bit key.
     */
    public const ALGO_A192GCM = 'A192GCM';

    /**
     * AES GCM using 256-bit key.
     */
    public const ALGO_A256GCM = 'A256GCM';

    /**
     * DEFLATE compression.
     */
    public const ALGO_DEFLATE = 'DEF';

    /**
     * Derive algorithm name from the header and optionally from the given JWK.
     *
     * @param Header $header Header
     * @param JWK    $jwk    Optional JWK
     *
     * @throws \UnexpectedValueException if algorithm parameter is not present
     *                                   or header and JWK algorithms differ
     *
     * @return string Algorithm name
     */
    public static function deriveAlgorithmName(Header $header, ?JWK $jwk = null): string
    {
        if ($header->hasAlgorithm()) {
            $alg = $header->algorithm()->value();
        }
        // if JWK is set, and has an algorithm parameter
        if (isset($jwk) && $jwk->hasAlgorithmParameter()) {
            $jwk_alg = $jwk->algorithmParameter()->value();
            // check that algorithms match
            if (isset($alg) && $alg !== $jwk_alg) {
                throw new \UnexpectedValueException(
                    "JWK algorithm '{$jwk_alg}' doesn't match" .
                         " the header's algorithm '{$alg}'.");
            }
            $alg = $jwk_alg;
        }
        if (!isset($alg)) {
            throw new \UnexpectedValueException('No algorithm parameter.');
        }
        return $alg;
    }
}
