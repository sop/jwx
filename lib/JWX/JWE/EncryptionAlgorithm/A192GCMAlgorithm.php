<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\EncryptionAlgorithm;

use Sop\GCM\Cipher\AES\AES192Cipher;
use Sop\GCM\Cipher\Cipher;
use Sop\JWX\JWA\JWA;

/**
 * Implements AES-GCM with 192-bit key.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-5.3
 */
class A192GCMAlgorithm extends AESGCMAlgorithm
{
    /**
     * {@inheritdoc}
     */
    public function encryptionAlgorithmParamValue(): string
    {
        return JWA::ALGO_A192GCM;
    }

    /**
     * {@inheritdoc}
     */
    public function keySize(): int
    {
        return 24;
    }

    /**
     * {@inheritdoc}
     */
    protected function _getGCMCipher(): Cipher
    {
        return new AES192Cipher();
    }
}
