<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\KeyAlgorithm;

use Sop\AESKW\AESKeyWrapAlgorithm;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyAlgorithm\Feature\RandomCEK;
use Sop\JWX\JWE\KeyManagementAlgorithm;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;

/**
 * Base class for algorithms implementing AES key wrap.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.4
 */
abstract class AESKWAlgorithm extends KeyManagementAlgorithm
{
    use RandomCEK;

    /**
     * Mapping from algorithm name to class name.
     *
     * @internal
     *
     * @var array
     */
    public const MAP_ALGO_TO_CLASS = [
        JWA::ALGO_A128KW => A128KWAlgorithm::class,
        JWA::ALGO_A192KW => A192KWAlgorithm::class,
        JWA::ALGO_A256KW => A256KWAlgorithm::class,
    ];

    /**
     * Key encryption key.
     *
     * @var string
     */
    protected $_kek;

    /**
     * Key wrapping algorithm.
     *
     * Lazily initialized.
     *
     * @var null|AESKeyWrapAlgorithm
     */
    protected $_kw;

    /**
     * Constructor.
     *
     * @param string $kek Key encryption key
     */
    public function __construct(string $kek)
    {
        if (strlen($kek) !== $this->_kekSize()) {
            throw new \LengthException(
                'Key encryption key must be ' . $this->_kekSize() . ' bytes.');
        }
        $this->_kek = $kek;
    }

    /**
     * Initialize from JWK.
     *
     * @throws \UnexpectedValueException
     *
     * @return self
     */
    public static function fromJWK(JWK $jwk, Header $header): KeyManagementAlgorithm
    {
        $jwk = SymmetricKeyJWK::fromJWK($jwk);
        $alg = JWA::deriveAlgorithmName($header, $jwk);
        if (!array_key_exists($alg, self::MAP_ALGO_TO_CLASS)) {
            throw new \UnexpectedValueException("Unsupported algorithm '{$alg}'.");
        }
        $cls = self::MAP_ALGO_TO_CLASS[$alg];
        return new $cls($jwk->key());
    }

    /**
     * {@inheritdoc}
     */
    public function headerParameters(): array
    {
        return array_merge(parent::headerParameters(),
            [AlgorithmParameter::fromAlgorithm($this)]);
    }

    /**
     * Get the size of the key encryption key in bytes.
     */
    abstract protected function _kekSize(): int;

    /**
     * Get key wrapping algorithm instance.
     */
    abstract protected function _AESKWAlgo(): AESKeyWrapAlgorithm;

    /**
     * Get key wrapping algorithm.
     */
    protected function _kw(): AESKeyWrapAlgorithm
    {
        if (!isset($this->_kw)) {
            $this->_kw = $this->_AESKWAlgo();
        }
        return $this->_kw;
    }

    /**
     * {@inheritdoc}
     */
    protected function _encryptKey(string $key, Header &$header): string
    {
        return $this->_kw()->wrap($key, $this->_kek);
    }

    /**
     * {@inheritdoc}
     */
    protected function _decryptKey(string $ciphertext, Header $header): string
    {
        return $this->_kw()->unwrap($ciphertext, $this->_kek);
    }
}
