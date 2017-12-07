<?php

declare(strict_types = 1);

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\JWK\RSA\RSAPublicKeyJWK;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;

/**
 * Base class for algorithms implementing signature with PKCS #1.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.3
 */
abstract class RSASSAPKCS1Algorithm extends OpenSSLSignatureAlgorithm
{
    /**
     * Mapping from algorithm name to class name.
     *
     * @internal
     *
     * @var array
     */
    const MAP_ALGO_TO_CLASS = array(
        /* @formatter:off */
        JWA::ALGO_RS256 => RS256Algorithm::class,
        JWA::ALGO_RS384 => RS384Algorithm::class,
        JWA::ALGO_RS512 => RS512Algorithm::class
        /* @formatter:on */
    );
    
    /**
     * Constructor.
     *
     * @param RSAPublicKeyJWK $pub_key
     * @param RSAPrivateKeyJWK $priv_key
     */
    protected function __construct(RSAPublicKeyJWK $pub_key,
        RSAPrivateKeyJWK $priv_key = null)
    {
        $this->_publicKey = $pub_key;
        $this->_privateKey = $priv_key;
    }
    
    /**
     * Initialize from a public key.
     *
     * @param RSAPublicKeyJWK $jwk
     * @return self
     */
    public static function fromPublicKey(RSAPublicKeyJWK $jwk): self
    {
        return new static($jwk);
    }
    
    /**
     * Initialize from a private key.
     *
     * @param RSAPrivateKeyJWK $jwk
     * @return self
     */
    public static function fromPrivateKey(RSAPrivateKeyJWK $jwk): self
    {
        return new static($jwk->publicKey(), $jwk);
    }
    
    /**
     *
     * @param JWK $jwk
     * @param Header $header
     * @throws \UnexpectedValueException
     * @return RSASSAPKCS1Algorithm
     */
    public static function fromJWK(JWK $jwk, Header $header): self
    {
        $alg = JWA::deriveAlgorithmName($header, $jwk);
        if (!array_key_exists($alg, self::MAP_ALGO_TO_CLASS)) {
            throw new \UnexpectedValueException("Unsupported algorithm '$alg'.");
        }
        $cls = self::MAP_ALGO_TO_CLASS[$alg];
        if ($jwk->has(...RSAPrivateKeyJWK::MANAGED_PARAMS)) {
            return $cls::fromPrivateKey(RSAPrivateKeyJWK::fromJWK($jwk));
        }
        return $cls::fromPublicKey(RSAPublicKeyJWK::fromJWK($jwk));
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
