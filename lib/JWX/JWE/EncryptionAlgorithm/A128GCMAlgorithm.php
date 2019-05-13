<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\EncryptionAlgorithm;

use Sop\GCM\Cipher\AES\AES128Cipher;
use Sop\GCM\Cipher\Cipher;
use Sop\JWX\JWA\JWA;

/**
 * Implements AES-GCM with 128-bit key.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-5.3
 */
class A128GCMAlgorithm extends AESGCMAlgorithm
{
    /**
     * {@inheritdoc}
     */
    public function encryptionAlgorithmParamValue(): string
    {
        return JWA::ALGO_A128GCM;
    }

    /**
     * {@inheritdoc}
     */
    public function keySize(): int
    {
        return 16;
    }

    /**
     * {@inheritdoc}
     */
    protected function _getGCMCipher(): Cipher
    {
        return new AES128Cipher();
    }
}
