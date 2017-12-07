<?php

declare(strict_types = 1);

namespace JWX\JWE\EncryptionAlgorithm;

use JWX\JWA\JWA;
use Sop\GCM\Cipher\Cipher;
use Sop\GCM\Cipher\AES\AES192Cipher;

/**
 * Implements AES-GCM with 192-bit key.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-5.3
 */
class A192GCMAlgorithm extends AESGCMAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    public function encryptionAlgorithmParamValue(): string
    {
        return JWA::ALGO_A192GCM;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function keySize(): int
    {
        return 24;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _getGCMCipher(): Cipher
    {
        return new AES192Cipher();
    }
}
