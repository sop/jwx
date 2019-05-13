<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\KeyAlgorithm;

use Sop\GCM\Cipher\AES\AES128Cipher;
use Sop\GCM\Cipher\Cipher;
use Sop\JWX\JWA\JWA;

/**
 * Implements key encryption with AES GCM using 128-bit key.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.7
 */
class A128GCMKWAlgorithm extends AESGCMKWAlgorithm
{
    /**
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_A128GCMKW;
    }

    /**
     * {@inheritdoc}
     */
    protected function _getGCMCipher(): Cipher
    {
        return new AES128Cipher();
    }

    /**
     * {@inheritdoc}
     */
    protected function _keySize(): int
    {
        return 16;
    }
}
