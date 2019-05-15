<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\EncryptionAlgorithm;

use Sop\GCM\AESGCM;
use Sop\GCM\Exception\AuthenticationException as GCMAuthException;
use Sop\JWX\JWE\ContentEncryptionAlgorithm;
use Sop\JWX\JWE\Exception\AuthenticationException;
use Sop\JWX\JWT\Parameter\EncryptionAlgorithmParameter;

/**
 * Base class for algorithms implementing AES in Galois/Counter mode.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-5.3
 */
abstract class AESGCMAlgorithm implements ContentEncryptionAlgorithm
{
    /**
     * {@inheritdoc}
     */
    public function encrypt(string $plaintext, string $key, string $iv,
        string $aad): array
    {
        $this->_validateKey($key);
        $this->_validateIV($iv);
        return AESGCM::encrypt($plaintext, $aad, $key, $iv, 16);
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $ciphertext, string $key, string $iv,
        string $aad, string $auth_tag): string
    {
        $this->_validateKey($key);
        $this->_validateIV($iv);
        try {
            $plaintext = AESGCM::decrypt($ciphertext, $auth_tag, $aad, $key, $iv);
        } catch (GCMAuthException $e) {
            throw new AuthenticationException('Message authentication failed.');
        }
        return $plaintext;
    }

    /**
     * {@inheritdoc}
     */
    public function ivSize(): int
    {
        return 12;
    }

    /**
     * {@inheritdoc}
     */
    public function headerParameters(): array
    {
        return [EncryptionAlgorithmParameter::fromAlgorithm($this)];
    }

    /**
     * Check that key is valid.
     *
     * @param string $key
     *
     * @throws \RuntimeException
     */
    final protected function _validateKey(string $key): void
    {
        if (strlen($key) !== $this->keySize()) {
            throw new \RuntimeException('Invalid key size.');
        }
    }

    /**
     * Check that IV is valid.
     *
     * @param string $iv
     *
     * @throws \RuntimeException
     */
    final protected function _validateIV(string $iv): void
    {
        if (strlen($iv) !== $this->ivSize()) {
            throw new \RuntimeException('Invalid IV length.');
        }
    }
}
