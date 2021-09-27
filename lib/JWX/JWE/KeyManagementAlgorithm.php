<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE;

use Sop\JWX\JWE\KeyAlgorithm\KeyAlgorithmFactory;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Header\HeaderParameters;
use Sop\JWX\JWT\Parameter\AlgorithmParameterValue;
use Sop\JWX\JWT\Parameter\KeyIDParameter;

/**
 * Base class for algorithms used for CEK management for the content encryption
 * algorithms.
 */
abstract class KeyManagementAlgorithm implements AlgorithmParameterValue, HeaderParameters
{
    /**
     * ID of the key used by the algorithm.
     *
     * If set, KeyID parameter shall be automatically inserted into JWE's
     * header.
     *
     * @var null|string
     */
    protected $_keyID;

    /**
     * Encrypt a key to be inserted into JWE header.
     *
     * @param string      $cek    Content encryption key
     * @param null|Header $header Optional reference to the Header variable,
     *                            which may be updated to contain parameters
     *                            specific to this encrypt invocation.
     *                            If the variable is referenced, but is a null,
     *                            it shall be initialized to an empty Header.
     *
     * @throws \RuntimeException For generic errors
     *
     * @return string Encrypted key
     */
    final public function encrypt(string $cek, Header &$header = null): string
    {
        if (!isset($header)) {
            $header = new Header();
        }
        return $this->_encryptKey($cek, $header);
    }

    /**
     * Decrypt a CEK from the encrypted data.
     *
     * @param string      $data   Encrypted key
     * @param null|Header $header Optional header containing parameters
     *                            required to decrypt the key
     *
     * @throws \RuntimeException For generic errors
     *
     * @return string Content encryption key
     */
    final public function decrypt(string $data, ?Header $header = null): string
    {
        if (!isset($header)) {
            $header = new Header();
        }
        return $this->_decryptKey($data, $header);
    }

    /**
     * Get content encryption key for the encryption.
     *
     * Returned key may be random depending on the key management algorithm.
     *
     * @param int $length Required key size in bytes
     */
    abstract public function cekForEncryption(int $length): string;

    /**
     * Initialize key management algorithm from a JWK and a header.
     */
    public static function fromJWK(JWK $jwk, Header $header): KeyManagementAlgorithm
    {
        $factory = new KeyAlgorithmFactory($header);
        return $factory->algoByKey($jwk);
    }

    /**
     * Get self with key ID.
     *
     * @param null|string $id Key ID or null to remove
     */
    public function withKeyID(?string $id): self
    {
        $obj = clone $this;
        $obj->_keyID = $id;
        return $obj;
    }

    /**
     * {@inheritdoc}
     */
    public function headerParameters(): array
    {
        $params = [];
        if (isset($this->_keyID)) {
            $params[] = new KeyIDParameter($this->_keyID);
        }
        return $params;
    }

    /**
     * Encrypt a key.
     *
     * @param string $key    Key to be encrypted
     * @param Header $header Reference to the Header variable, that shall
     *                       be updated to contain parameters specific to the encryption
     *
     * @return string Ciphertext
     */
    abstract protected function _encryptKey(string $key, Header &$header): string;

    /**
     * Decrypt a key.
     *
     * @param string $ciphertext Ciphertext of the encrypted key
     * @param Header $header     Header possibly containing encoding specific
     *                           parameters
     *
     * @return string Plaintext key
     */
    abstract protected function _decryptKey(string $ciphertext, Header $header): string;
}
