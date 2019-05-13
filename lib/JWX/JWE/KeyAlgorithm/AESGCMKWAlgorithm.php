<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\KeyAlgorithm;

use Sop\GCM\Cipher\Cipher;
use Sop\GCM\GCM;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyAlgorithm\Feature\RandomCEK;
use Sop\JWX\JWE\KeyManagementAlgorithm;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;
use Sop\JWX\JWT\Parameter\AuthenticationTagParameter;
use Sop\JWX\JWT\Parameter\InitializationVectorParameter;

/**
 * Base class for AES GCM key encryption algorithms.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.7
 */
abstract class AESGCMKWAlgorithm extends KeyManagementAlgorithm
{
    use RandomCEK;

    /**
     * Mapping from algorithm name to class name.
     *
     * @internal
     *
     * @var array
     */
    const MAP_ALGO_TO_CLASS = [
        JWA::ALGO_A128GCMKW => A128GCMKWAlgorithm::class,
        JWA::ALGO_A192GCMKW => A192GCMKWAlgorithm::class,
        JWA::ALGO_A256GCMKW => A256GCMKWAlgorithm::class,
    ];

    /**
     * Required IV size in bytes.
     *
     * @var int
     */
    const IV_SIZE = 12;

    /**
     * Authentication tag size in bytes.
     *
     * @var int
     */
    const AUTH_TAG_SIZE = 16;

    /**
     * Key encryption key.
     *
     * @var string
     */
    protected $_kek;

    /**
     * Initialization vector.
     *
     * @var string
     */
    protected $_iv;

    /**
     * Constructor.
     *
     * @param string $kek Key encryption key
     * @param string $iv  Initialization vector
     */
    public function __construct(string $kek, string $iv)
    {
        if (strlen($kek) !== $this->_keySize()) {
            throw new \LengthException('Invalid key size.');
        }
        if (self::IV_SIZE !== strlen($iv)) {
            throw new \LengthException('Initialization vector must be 96 bits.');
        }
        $this->_kek = $kek;
        $this->_iv = $iv;
    }

    /**
     * Initialize from JWK.
     *
     * @param JWK    $jwk
     * @param Header $header
     *
     * @throws \UnexpectedValueException
     *
     * @return self
     */
    public static function fromJWK(JWK $jwk, Header $header): KeyManagementAlgorithm
    {
        $jwk = SymmetricKeyJWK::fromJWK($jwk);
        if (!$header->hasInitializationVector()) {
            throw new \UnexpectedValueException('No initialization vector.');
        }
        $iv = $header->initializationVector()->initializationVector();
        $alg = JWA::deriveAlgorithmName($header, $jwk);
        if (!array_key_exists($alg, self::MAP_ALGO_TO_CLASS)) {
            throw new \UnexpectedValueException("Unsupported algorithm '{$alg}'.");
        }
        $cls = self::MAP_ALGO_TO_CLASS[$alg];
        return new $cls($jwk->key(), $iv);
    }

    /**
     * Initialize from key encryption key with random IV.
     *
     * Key size must match the underlying cipher.
     *
     * @param string $key Key encryption key
     *
     * @return self
     */
    public static function fromKey(string $key): self
    {
        $iv = openssl_random_pseudo_bytes(self::IV_SIZE);
        return new static($key, $iv);
    }

    /**
     * {@inheritdoc}
     */
    public function headerParameters(): array
    {
        return array_merge(parent::headerParameters(),
            [AlgorithmParameter::fromAlgorithm($this),
                InitializationVectorParameter::fromString($this->_iv), ]);
    }

    /**
     * Get GCM Cipher instance.
     *
     * @return Cipher
     */
    abstract protected function _getGCMCipher(): Cipher;

    /**
     * Get the required key size.
     *
     * @return int
     */
    abstract protected function _keySize(): int;

    /**
     * Get GCM instance.
     *
     * @return GCM
     */
    final protected function _getGCM(): GCM
    {
        return new GCM($this->_getGCMCipher(), self::AUTH_TAG_SIZE);
    }

    /**
     * {@inheritdoc}
     */
    protected function _encryptKey(string $key, Header &$header): string
    {
        [$ciphertext, $auth_tag] = $this->_getGCM()
            ->encrypt($key, '', $this->_kek, $this->_iv);
        // insert authentication tag to the header
        $header = $header->withParameters(
            AuthenticationTagParameter::fromString($auth_tag));
        return $ciphertext;
    }

    /**
     * {@inheritdoc}
     */
    protected function _decryptKey(string $ciphertext, Header $header): string
    {
        if (!$header->hasAuthenticationTag()) {
            throw new \RuntimeException(
                "Header doesn't contain authentication tag.");
        }
        $auth_tag = $header->authenticationTag()->authenticationTag();
        return $this->_getGCM()
            ->decrypt($ciphertext, $auth_tag, '', $this->_kek, $this->_iv);
    }
}
