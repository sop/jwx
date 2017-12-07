<?php

declare(strict_types = 1);

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWA\JWA;
use Sop\AESKW\AESKW192;
use Sop\AESKW\AESKeyWrapAlgorithm;

/**
 * Implements AES key wrap with 192-bit key.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.4
 */
class A192KWAlgorithm extends AESKWAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _kekSize(): int
    {
        return 24;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _AESKWAlgo(): AESKeyWrapAlgorithm
    {
        return new AESKW192();
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_A192KW;
    }
}
