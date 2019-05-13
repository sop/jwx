<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\KeyAlgorithm;

use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyManagementAlgorithm;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;

/**
 * Algorithm to carry CEK in plaintext.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.5
 */
class DirectCEKAlgorithm extends KeyManagementAlgorithm
{
    /**
     * Content encryption key.
     *
     * @var string
     */
    protected $_cek;

    /**
     * Constructor.
     *
     * @param string $cek Content encryption key
     */
    public function __construct(string $cek)
    {
        $this->_cek = $cek;
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
        $alg = JWA::deriveAlgorithmName($header);
        if (JWA::ALGO_DIR !== $alg) {
            throw new \UnexpectedValueException("Invalid algorithm '{$alg}'.");
        }
        return new self($jwk->key());
    }

    /**
     * Get content encryption key.
     *
     * @return string
     */
    public function cek(): string
    {
        return $this->_cek;
    }

    /**
     * {@inheritdoc}
     */
    public function cekForEncryption(int $length): string
    {
        if (strlen($this->_cek) !== $length) {
            throw new \UnexpectedValueException('Invalid key length.');
        }
        return $this->_cek;
    }

    /**
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_DIR;
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
     * {@inheritdoc}
     */
    protected function _encryptKey(string $key, Header &$header): string
    {
        if ($key !== $this->_cek) {
            throw new \LogicException("Content encryption key doesn't match.");
        }
        return '';
    }

    /**
     * {@inheritdoc}
     */
    protected function _decryptKey(string $ciphertext, Header $header): string
    {
        if ('' !== $ciphertext) {
            throw new \UnexpectedValueException(
                'Encrypted key must be an empty octet sequence.');
        }
        return $this->_cek;
    }
}
