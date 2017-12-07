<?php

declare(strict_types = 1);

namespace JWX\JWE\EncryptionAlgorithm;

use JWX\JWE\ContentEncryptionAlgorithm;
use JWX\JWE\Exception\AuthenticationException;
use JWX\JWT\Parameter\EncryptionAlgorithmParameter;
use Sop\GCM\GCM;
use Sop\GCM\Cipher\Cipher;
use Sop\GCM\Exception\AuthenticationException as GCMAuthException;

/**
 * Base class for algorithms implementing AES in Galois/Counter mode.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-5.3
 */
abstract class AESGCMAlgorithm implements ContentEncryptionAlgorithm
{
    /**
     * Get GCM Cipher instance.
     *
     * @return Cipher
     */
    abstract protected function _getGCMCipher(): Cipher;
    
    /**
     * Get GCM instance.
     *
     * @return GCM
     */
    final protected function _getGCM(): GCM
    {
        return new GCM($this->_getGCMCipher(), 16);
    }
    
    /**
     * Check that key is valid.
     *
     * @param string $key
     * @throws \RuntimeException
     */
    final protected function _validateKey(string $key)
    {
        if (strlen($key) != $this->keySize()) {
            throw new \RuntimeException("Invalid key size.");
        }
    }
    
    /**
     * Check that IV is valid.
     *
     * @param string $iv
     * @throws \RuntimeException
     */
    final protected function _validateIV(string $iv)
    {
        if (strlen($iv) != $this->ivSize()) {
            throw new \RuntimeException("Invalid IV length.");
        }
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function encrypt(string $plaintext, string $key, string $iv,
        string $aad): array
    {
        $this->_validateKey($key);
        $this->_validateIV($iv);
        list($ciphertext, $auth_tag) = $this->_getGCM()->encrypt($plaintext,
            $aad, $key, $iv);
        return [$ciphertext, $auth_tag];
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function decrypt(string $ciphertext, string $key, string $iv,
        string $aad, string $auth_tag): string
    {
        $this->_validateKey($key);
        $this->_validateIV($iv);
        try {
            $plaintext = $this->_getGCM()->decrypt($ciphertext, $auth_tag, $aad,
                $key, $iv);
        } catch (GCMAuthException $e) {
            throw new AuthenticationException("Message authentication failed.");
        }
        return $plaintext;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function ivSize(): int
    {
        return 12;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function headerParameters(): array
    {
        return array(EncryptionAlgorithmParameter::fromAlgorithm($this));
    }
}
