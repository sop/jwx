<?php

namespace JWX\JWE\EncryptionAlgorithm;

use GCM\Cipher\AES\AES128Cipher;
use JWX\JWA\JWA;

/**
 * Implements AES-GCM with 128-bit key.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-5.3
 */
class A128GCMAlgorithm extends AESGCMAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    public function encryptionAlgorithmParamValue()
    {
        return JWA::ALGO_A128GCM;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function keySize()
    {
        return 16;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _getGCMCipher()
    {
        return new AES128Cipher();
    }
}
