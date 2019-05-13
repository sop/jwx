<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\KeyAlgorithm;

use Sop\AESKW\AESKeyWrapAlgorithm;
use Sop\AESKW\AESKW256;
use Sop\JWX\JWA\JWA;

/**
 * Implements PBES2 with HMAC SHA-512 and "A256KW" wrapping.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.8
 */
class PBES2HS512A256KWAlgorithm extends PBES2Algorithm
{
    /**
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_PBES2_HS512_A256KW;
    }

    /**
     * {@inheritdoc}
     */
    protected function _hashAlgo(): string
    {
        return 'sha512';
    }

    /**
     * {@inheritdoc}
     */
    protected function _keyLength(): int
    {
        return 32;
    }

    /**
     * {@inheritdoc}
     */
    protected function _kwAlgo(): AESKeyWrapAlgorithm
    {
        return new AESKW256();
    }
}
