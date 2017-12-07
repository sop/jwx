<?php

declare(strict_types = 1);

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWA\JWA;
use Sop\AESKW\AESKW128;
use Sop\AESKW\AESKeyWrapAlgorithm;

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
    protected function _kekSize(): int
    {
        return 16;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _AESKWAlgo(): AESKeyWrapAlgorithm
    {
        return new AESKW128();
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_A128KW;
    }
}
