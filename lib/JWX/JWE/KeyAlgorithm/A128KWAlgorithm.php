<?php

namespace JWX\JWE\KeyAlgorithm;

use AESKW\AESKW128;
use JWX\JWA\JWA;

/**
 * Implements AES key wrap with 128-bit key.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.4
 */
class A128KWAlgorithm extends AESKWAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _kekSize()
    {
        return 16;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _AESKWAlgo()
    {
        return new AESKW128();
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue()
    {
        return JWA::ALGO_A128KW;
    }
}
