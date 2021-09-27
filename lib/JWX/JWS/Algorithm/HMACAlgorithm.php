<?php

declare(strict_types = 1);

namespace Sop\JWX\JWS\Algorithm;

use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWS\SignatureAlgorithm;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;

/**
 * Base class for algorithms implementing HMAC signature.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-3.2
 */
abstract class HMACAlgorithm extends SignatureAlgorithm
{
    /**
     * Mapping from algorithm name to class name.
     *
     * @internal
     *
     * @var array
     */
    public const MAP_ALGO_TO_CLASS = [
        JWA::ALGO_HS256 => HS256Algorithm::class,
        JWA::ALGO_HS384 => HS384Algorithm::class,
        JWA::ALGO_HS512 => HS512Algorithm::class,
    ];

    /**
     * Shared secret key.
     *
     * @var string
     */
    protected $_key;

    /**
     * Constructor.
     *
     * @param string $key Shared secret key
     */
    public function __construct(string $key)
    {
        $this->_key = $key;
    }

    /**
     * {@inheritdoc}
     *
     * @return self
     */
    public static function fromJWK(JWK $jwk, Header $header): SignatureAlgorithm
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
     *
     * @throws \RuntimeException For generic errors
     */
    public function computeSignature(string $data): string
    {
        $result = @hash_hmac($this->_hashAlgo(), $data, $this->_key, true);
        if (false === $result) {
            $err = error_get_last();
            $msg = isset($err) && __FILE__ === $err['file'] ? $err['message'] : null;
            throw new \RuntimeException($msg ?? 'hash_hmac() failed.');
        }
        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function validateSignature(string $data, string $signature): bool
    {
        return $this->computeSignature($data) === $signature;
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
     * Get algorithm name recognized by the Hash extension.
     */
    abstract protected function _hashAlgo(): string;
}
