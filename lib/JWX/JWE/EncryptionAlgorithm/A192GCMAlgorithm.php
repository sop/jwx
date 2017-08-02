<?php

namespace JWX\JWE\EncryptionAlgorithm;

use GCM\Cipher\AES\AES192Cipher;
use JWX\JWA\JWA;

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
    public function encryptionAlgorithmParamValue()
    {
        return JWA::ALGO_A192GCM;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function keySize()
    {
        return 24;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _getGCMCipher()
    {
        return new AES192Cipher();
    }
}
