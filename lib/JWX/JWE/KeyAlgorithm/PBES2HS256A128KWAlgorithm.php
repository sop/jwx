<?php

namespace JWX\JWE\KeyAlgorithm;

use AESKW\AESKW128;
use JWX\JWA\JWA;

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
    protected function _hashAlgo()
    {
        return "sha256";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _keyLength()
    {
        return 16;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _kwAlgo()
    {
        return new AESKW128();
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue()
    {
        return JWA::ALGO_PBES2_HS256_A128KW;
    }
}
