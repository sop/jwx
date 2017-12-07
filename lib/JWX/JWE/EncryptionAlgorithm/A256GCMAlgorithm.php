<?php

declare(strict_types = 1);

namespace JWX\JWE\EncryptionAlgorithm;

use JWX\JWA\JWA;
use Sop\GCM\Cipher\Cipher;
use Sop\GCM\Cipher\AES\AES256Cipher;

/**
 * Implements AES-GCM with 256-bit key.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-5.3
 */
class A256GCMAlgorithm extends AESGCMAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    public function encryptionAlgorithmParamValue(): string
    {
        return JWA::ALGO_A256GCM;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function keySize(): int
    {
        return 32;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _getGCMCipher(): Cipher
    {
        return new AES256Cipher();
    }
}
