<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\KeyAlgorithm;

use Sop\GCM\Cipher\AES\AES256Cipher;
use Sop\GCM\Cipher\Cipher;
use Sop\JWX\JWA\JWA;

/**
 * Implements key encryption with AES GCM using 256-bit key.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.7
 */
class A256GCMKWAlgorithm extends AESGCMKWAlgorithm
{
    /**
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_A256GCMKW;
    }

    /**
     * {@inheritdoc}
     */
    protected function _getGCMCipher(): Cipher
    {
        return new AES256Cipher();
    }

    /**
     * {@inheritdoc}
     */
    protected function _keySize(): int
    {
        return 32;
    }
}
