<?php

declare(strict_types = 1);

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWA\JWA;
use Sop\AESKW\AESKW128;
use Sop\AESKW\AESKeyWrapAlgorithm;

/**
 * Implements PBES2 with HMAC SHA-256 and "A128KW" wrapping.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.8
 */
class PBES2HS256A128KWAlgorithm extends PBES2Algorithm
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _hashAlgo(): string
    {
        return "sha256";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _keyLength(): int
    {
        return 16;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _kwAlgo(): AESKeyWrapAlgorithm
    {
        return new AESKW128();
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_PBES2_HS256_A128KW;
    }
}
