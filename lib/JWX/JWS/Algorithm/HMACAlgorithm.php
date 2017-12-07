<?php

declare(strict_types = 1);

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWS\SignatureAlgorithm;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;

/**
 * Base class for algorithms implementing HMAC signature.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.2
 */
abstract class HMACAlgorithm extends SignatureAlgorithm
{
    /**
     * Shared secret key.
     *
     * @var string $_key
     */
    protected $_key;
    
    /**
     * Mapping from algorithm name to class name.
     *
     * @internal
     *
     * @var array
     */
    const MAP_ALGO_TO_CLASS = array(
        /* @formatter:off */
        JWA::ALGO_HS256 => HS256Algorithm::class, 
        JWA::ALGO_HS384 => HS384Algorithm::class, 
        JWA::ALGO_HS512 => HS512Algorithm::class
        /* @formatter:on */
    );
    
    /**
     * Get algorithm name recognized by the Hash extension.
     *
     * @return string
     */
    abstract protected function _hashAlgo(): string;
    
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
     *
     * {@inheritdoc}
     */
    public static function fromJWK(JWK $jwk, Header $header): self
    {
        $jwk = SymmetricKeyJWK::fromJWK($jwk);
        $alg = JWA::deriveAlgorithmName($header, $jwk);
        if (!array_key_exists($alg, self::MAP_ALGO_TO_CLASS)) {
            throw new \UnexpectedValueException("Unsupported algorithm '$alg'.");
        }
        $cls = self::MAP_ALGO_TO_CLASS[$alg];
        return new $cls($jwk->key());
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function computeSignature(string $data): string
    {
        $result = @hash_hmac($this->_hashAlgo(), $data, $this->_key, true);
        if (false === $result) {
            $err = error_get_last();
            $msg = isset($err) && __FILE__ == $err['file'] ? $err['message'] : null;
            throw new \RuntimeException($msg ?? 'hash_hmac() failed.');
        }
        return $result;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function validateSignature(string $data, string $signature): bool
    {
        return $this->computeSignature($data) === $signature;
    }
    
    /**
     *
     * @see \JWX\JWS\SignatureAlgorithm::headerParameters()
     * @return \JWX\JWT\Parameter\JWTParameter[]
     */
    public function headerParameters(): array
    {
        return array_merge(parent::headerParameters(),
            array(AlgorithmParameter::fromAlgorithm($this)));
    }
}
