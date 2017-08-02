<?php

namespace JWX\JWE\EncryptionAlgorithm;

use JWX\JWA\JWA;

/**
 * Implements AES with 192-bit key in CBC mode with HMAC SHA-384 authentication.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-5.2.4
 */
class A192CBCHS384Algorithm extends AESCBCAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    public function keySize()
    {
        return 48;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function encryptionAlgorithmParamValue()
    {
        return JWA::ALGO_A192CBC_HS384;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _cipherMethod()
    {
        return "AES-192-CBC";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _hashAlgo()
    {
        return "sha384";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _encKeyLen()
    {
        return 24;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _macKeyLen()
    {
        return 24;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _tagLen()
    {
        return 24;
    }
}
