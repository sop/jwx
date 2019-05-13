<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\EncryptionAlgorithm;

use Sop\JWX\JWA\JWA;

/**
 * Implements AES with 256-bit key in CBC mode with HMAC SHA-512 authentication.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-5.2.5
 */
class A256CBCHS512Algorithm extends AESCBCAlgorithm
{
    /**
     * {@inheritdoc}
     */
    public function keySize(): int
    {
        return 64;
    }

    /**
     * {@inheritdoc}
     */
    public function encryptionAlgorithmParamValue(): string
    {
        return JWA::ALGO_A256CBC_HS512;
    }

    /**
     * {@inheritdoc}
     */
    protected function _cipherMethod(): string
    {
        return 'aes-256-cbc';
    }

    /**
     * {@inheritdoc}
     */
    protected function _hashAlgo(): string
    {
        return 'sha512';
    }

    /**
     * {@inheritdoc}
     */
    protected function _encKeyLen(): int
    {
        return 32;
    }

    /**
     * {@inheritdoc}
     */
    protected function _macKeyLen(): int
    {
        return 32;
    }

    /**
     * {@inheritdoc}
     */
    protected function _tagLen(): int
    {
        return 32;
    }
}
