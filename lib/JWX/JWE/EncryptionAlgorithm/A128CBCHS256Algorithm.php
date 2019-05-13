<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\EncryptionAlgorithm;

use Sop\JWX\JWA\JWA;

/**
 * Implements AES with 128-bit key in CBC mode with HMAC SHA-256 authentication.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-5.2.3
 */
class A128CBCHS256Algorithm extends AESCBCAlgorithm
{
    /**
     * {@inheritdoc}
     */
    public function keySize(): int
    {
        return 32;
    }

    /**
     * {@inheritdoc}
     */
    public function encryptionAlgorithmParamValue(): string
    {
        return JWA::ALGO_A128CBC_HS256;
    }

    /**
     * {@inheritdoc}
     */
    protected function _cipherMethod(): string
    {
        return 'aes-128-cbc';
    }

    /**
     * {@inheritdoc}
     */
    protected function _hashAlgo(): string
    {
        return 'sha256';
    }

    /**
     * {@inheritdoc}
     */
    protected function _encKeyLen(): int
    {
        return 16;
    }

    /**
     * {@inheritdoc}
     */
    protected function _macKeyLen(): int
    {
        return 16;
    }

    /**
     * {@inheritdoc}
     */
    protected function _tagLen(): int
    {
        return 16;
    }
}
