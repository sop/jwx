<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\KeyAlgorithm;

use Sop\AESKW\AESKeyWrapAlgorithm;
use Sop\AESKW\AESKW128;
use Sop\JWX\JWA\JWA;

/**
 * Implements AES key wrap with 128-bit key.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.4
 */
class A128KWAlgorithm extends AESKWAlgorithm
{
    /**
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_A128KW;
    }

    /**
     * {@inheritdoc}
     */
    protected function _kekSize(): int
    {
        return 16;
    }

    /**
     * {@inheritdoc}
     */
    protected function _AESKWAlgo(): AESKeyWrapAlgorithm
    {
        return new AESKW128();
    }
}
