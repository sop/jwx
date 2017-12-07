<?php

declare(strict_types = 1);

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
    public function keySize(): int
    {
        return 48;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function encryptionAlgorithmParamValue(): string
    {
        return JWA::ALGO_A192CBC_HS384;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _cipherMethod(): string
    {
        return "AES-192-CBC";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _hashAlgo(): string
    {
        return "sha384";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _encKeyLen(): int
    {
        return 24;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _macKeyLen(): int
    {
        return 24;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _tagLen(): int
    {
        return 24;
    }
}
