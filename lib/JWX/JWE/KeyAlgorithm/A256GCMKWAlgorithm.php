<?php

namespace JWX\JWE\KeyAlgorithm;

use GCM\Cipher\AES\AES256Cipher;
use JWX\JWA\JWA;

/**
 * Implements key encryption with AES GCM using 256-bit key.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.7
 */
class A256GCMKWAlgorithm extends AESGCMKWAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _getGCMCipher()
    {
        return new AES256Cipher();
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _keySize()
    {
        return 32;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue()
    {
        return JWA::ALGO_A256GCMKW;
    }
}
