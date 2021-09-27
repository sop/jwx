<?php

declare(strict_types = 1);

namespace Sop\JWX\JWS\Algorithm;

use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\RSA\RSAPrivateKeyJWK;
use Sop\JWX\JWK\RSA\RSAPublicKeyJWK;
use Sop\JWX\JWS\SignatureAlgorithm;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;

/**
 * Base class for algorithms implementing signature with PKCS #1.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-3.3
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
    public const MAP_ALGO_TO_CLASS = [
        JWA::ALGO_RS256 => RS256Algorithm::class,
        JWA::ALGO_RS384 => RS384Algorithm::class,
        JWA::ALGO_RS512 => RS512Algorithm::class,
    ];

    /**
     * Constructor.
     *
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
     */
    public static function fromPublicKey(RSAPublicKeyJWK $jwk): self
    {
        return new static($jwk);
    }

    /**
     * Initialize from a private key.
     */
    public static function fromPrivateKey(RSAPrivateKeyJWK $jwk): self
    {
        return new static($jwk->publicKey(), $jwk);
    }

    /**
     * {@inheritdoc}
     *
     * @return self
     */
    public static function fromJWK(JWK $jwk, Header $header): SignatureAlgorithm
    {
        $alg = JWA::deriveAlgorithmName($header, $jwk);
        if (!array_key_exists($alg, self::MAP_ALGO_TO_CLASS)) {
            throw new \UnexpectedValueException("Unsupported algorithm '{$alg}'.");
        }
        $cls = self::MAP_ALGO_TO_CLASS[$alg];
        if ($jwk->has(...RSAPrivateKeyJWK::MANAGED_PARAMS)) {
            return $cls::fromPrivateKey(RSAPrivateKeyJWK::fromJWK($jwk));
        }
        return $cls::fromPublicKey(RSAPublicKeyJWK::fromJWK($jwk));
    }

    /**
     * {@inheritdoc}
     */
    public function headerParameters(): array
    {
        return array_merge(parent::headerParameters(),
            [AlgorithmParameter::fromAlgorithm($this)]);
    }
}
