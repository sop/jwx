<?php

declare(strict_types = 1);

namespace Sop\JWX\JWS\Algorithm;

use Sop\JWX\JWK\Asymmetric\PrivateKeyJWK;
use Sop\JWX\JWK\Asymmetric\PublicKeyJWK;
use Sop\JWX\JWS\SignatureAlgorithm;

/**
 * Base class for algorithms employing asymmetric signature computation
 * using OpenSSL extension.
 */
abstract class OpenSSLSignatureAlgorithm extends SignatureAlgorithm
{
    /**
     * Public key.
     *
     * @var PublicKeyJWK
     */
    protected $_publicKey;

    /**
     * Private key.
     *
     * @var null|PrivateKeyJWK
     */
    protected $_privateKey;

    /**
     * {@inheritdoc}
     *
     * @throws \LogicException   If private key was not provided
     * @throws \RuntimeException For generic errors
     */
    public function computeSignature(string $data): string
    {
        /*
         * NOTE: OpenSSL uses PKCS #1 v1.5 padding by default, so no explicit
         * padding is required by sign and verify operations.
         */
        if (!isset($this->_privateKey)) {
            throw new \LogicException('Private key not set.');
        }
        $key = openssl_pkey_get_private($this->_privateKey->toPEM()->string());
        if (false === $key) {
            throw new \RuntimeException(
                'openssl_pkey_get_private() failed: ' .
                     $this->_getLastOpenSSLError());
        }
        $result = @openssl_sign($data, $signature, $key, $this->_mdMethod());
        if (!$result) {
            throw new \RuntimeException(
                'openssl_sign() failed: ' . $this->_getLastOpenSSLError());
        }
        return $signature;
    }

    /**
     * {@inheritdoc}
     *
     * @throws \RuntimeException For generic errors
     */
    public function validateSignature(string $data, string $signature): bool
    {
        $key = openssl_pkey_get_public($this->_publicKey->toPEM()->string());
        if (false === $key) {
            throw new \RuntimeException(
                'openssl_pkey_get_public() failed: ' .
                     $this->_getLastOpenSSLError());
        }
        $result = @openssl_verify($data, $signature, $key, $this->_mdMethod());
        if (false === $result || -1 == $result) {
            throw new \RuntimeException(
                'openssl_verify() failed: ' . $this->_getLastOpenSSLError());
        }
        return 1 == $result;
    }

    /**
     * Get the signature algorithm identifier supported by OpenSSL.
     *
     * @return int
     */
    abstract protected function _mdMethod(): int;

    /**
     * Get the last OpenSSL error message.
     *
     * @return null|string
     */
    protected function _getLastOpenSSLError(): ?string
    {
        $msg = null;
        while (false !== ($err = openssl_error_string())) {
            $msg = $err;
        }
        return $msg;
    }
}
