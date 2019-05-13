<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\KeyAlgorithm;

use Sop\AESKW\AESKeyWrapAlgorithm;
use Sop\AESKW\AESKW192;
use Sop\JWX\JWA\JWA;

/**
 * Implements PBES2 with HMAC SHA-384 and "A192KW" wrapping.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.8
 */
class PBES2HS384A192KWAlgorithm extends PBES2Algorithm
{
    /**
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_PBES2_HS384_A192KW;
    }

    /**
     * {@inheritdoc}
     */
    protected function _hashAlgo(): string
    {
        return 'sha384';
    }

    /**
     * {@inheritdoc}
     */
    protected function _keyLength(): int
    {
        return 24;
    }

    /**
     * {@inheritdoc}
     */
    protected function _kwAlgo(): AESKeyWrapAlgorithm
    {
        return new AESKW192();
    }
}
