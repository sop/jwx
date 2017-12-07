<?php

declare(strict_types = 1);

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWA\JWA;
use Sop\GCM\Cipher\Cipher;
use Sop\GCM\Cipher\AES\AES192Cipher;

/**
 * Implements key encryption with AES GCM using 192-bit key.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.7
 */
class A192GCMKWAlgorithm extends AESGCMKWAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _getGCMCipher(): Cipher
    {
        return new AES192Cipher();
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _keySize(): int
    {
        return 24;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_A192GCMKW;
    }
}
