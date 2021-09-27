<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\RSA;

use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPublicKey;
use Sop\JWX\JWK\Asymmetric\PublicKeyJWK;
use Sop\JWX\JWK\Parameter\ExponentParameter;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\KeyTypeParameter;
use Sop\JWX\JWK\Parameter\ModulusParameter;

/**
 * Class representing RSA public key as a JWK.
 *
 * @see https://tools.ietf.org/html/rfc7517#section-4
 * @see https://tools.ietf.org/html/rfc7518#section-6.3
 * @see https://tools.ietf.org/html/rfc7518#section-6.3.1
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
    public const MANAGED_PARAMS = [
        JWKParameter::PARAM_KEY_TYPE,
        JWKParameter::PARAM_MODULUS,
        JWKParameter::PARAM_EXPONENT,
    ];

    /**
     * Constructor.
     *
     * @param JWKParameter ...$params
     *
     * @throws \UnexpectedValueException If missing required parameter
     */
    public function __construct(JWKParameter ...$params)
    {
        parent::__construct(...$params);
        foreach (self::MANAGED_PARAMS as $name) {
            if (!$this->has($name)) {
                throw new \UnexpectedValueException(
                    "Missing '{$name}' parameter.");
            }
        }
        if (KeyTypeParameter::TYPE_RSA !== $this->keyTypeParameter()->value()) {
            throw new \UnexpectedValueException('Invalid key type.');
        }
    }

    /**
     * Initialize from RSAPublicKey.
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
     */
    public static function fromPEM(PEM $pem): self
    {
        return self::fromRSAPublicKey(RSAPublicKey::fromPEM($pem));
    }

    /**
     * Convert JWK to PEM.
     */
    public function toPEM(): PEM
    {
        $n = $this->modulusParameter()->number()->base10();
        $e = $this->exponentParameter()->number()->base10();
        $pk = new RSAPublicKey($n, $e);
        return PublicKeyInfo::fromPublicKey($pk)->toPEM();
    }
}
