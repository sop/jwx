<?php

declare(strict_types = 1);

namespace JWX\JWE;

use JWX\JWT\Header\HeaderParameters;
use JWX\JWT\Parameter\EncryptionAlgorithmParameterValue;

/**
 * Interface for algorithms that may be used to encrypt and decrypt JWE payload.
 */
interface ContentEncryptionAlgorithm extends 
    EncryptionAlgorithmParameterValue,
    HeaderParameters
{
    /**
     * Encrypt plaintext.
     *
     * @param string $plaintext Data to encrypt
     * @param string $key Encryption key
     * @param string $iv Initialization vector
     * @param string $aad Additional authenticated data
     * @return array Tuple of ciphertext and authentication tag
     */
    public function encrypt(string $plaintext, string $key, string $iv,
        string $aad);
    
    /**
     * Decrypt ciphertext.
     *
     * @param string $ciphertext Data to decrypt
     * @param string $key Encryption key
     * @param string $iv Initialization vector
     * @param string $aad Additional authenticated data
     * @param string $auth_tag Authentication tag to compare
     * @return string Plaintext
     */
    public function decrypt(string $ciphertext, string $key, string $iv,
        string $aad, string $auth_tag);
    
    /**
     * Get the required key size in bytes.
     *
     * @return int
     */
    public function keySize(): int;
    
    /**
     * Get the required IV size in bytes.
     *
     * @return int
     */
    public function ivSize(): int;
}
