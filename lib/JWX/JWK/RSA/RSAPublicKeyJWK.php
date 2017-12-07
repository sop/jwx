<?php

declare(strict_types = 1);

namespace JWX\JWK\RSA;

use JWX\JWK\Asymmetric\PublicKeyJWK;
use JWX\JWK\Parameter\ExponentParameter;
use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\KeyTypeParameter;
use JWX\JWK\Parameter\ModulusParameter;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPublicKey;

/**
 * Class representing RSA public key as a JWK.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4
 * @link https://tools.ietf.org/html/rfc7518#section-6.3
 * @link https://tools.ietf.org/html/rfc7518#section-6.3.1
 */
class RSAPublicKeyJWK extends PublicKeyJWK
{
    /**
     * Parameter names managed by this class.
     *
     * @internal
     *
     * @var string[]
     */
    const MANAGED_PARAMS = array(
        /* @formatter:off */
        JWKParameter::PARAM_KEY_TYPE,
        JWKParameter::PARAM_MODULUS,
        JWKParameter::PARAM_EXPONENT
        /* @formatter:on */
    );
    
    /**
     * Constructor.
     *
     * @param JWKParameter ...$params
     * @throws \UnexpectedValueException If missing required parameter
     */
    public function __construct(JWKParameter ...$params)
    {
        parent::__construct(...$params);
        foreach (self::MANAGED_PARAMS as $name) {
            if (!$this->has($name)) {
                throw new \UnexpectedValueException("Missing '$name' parameter.");
            }
        }
        if ($this->keyTypeParameter()->value() != KeyTypeParameter::TYPE_RSA) {
            throw new \UnexpectedValueException("Invalid key type.");
        }
    }
    
    /**
     * Initialize from RSAPublicKey.
     *
     * @param RSAPublicKey $pk
     * @return self
     */
    public static function fromRSAPublicKey(RSAPublicKey $pk): self
    {
        $n = ModulusParameter::fromNumber($pk->modulus());
        $e = ExponentParameter::fromNumber($pk->publicExponent());
        $key_type = new KeyTypeParameter(KeyTypeParameter::TYPE_RSA);
        return new self($key_type, $n, $e);
    }
    
    /**
     * Initialize from PEM.
     *
     * @param PEM $pem
     * @return self
     */
    public static function fromPEM(PEM $pem): self
    {
        return self::fromRSAPublicKey(RSAPublicKey::fromPEM($pem));
    }
    
    /**
     * Convert JWK to PEM.
     *
     * @return PEM
     */
    public function toPEM(): PEM
    {
        $n = $this->modulusParameter()
            ->number()
            ->base10();
        $e = $this->exponentParameter()
            ->number()
            ->base10();
        $pk = new RSAPublicKey($n, $e);
        return PublicKeyInfo::fromPublicKey($pk)->toPEM();
    }
}
