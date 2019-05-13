<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\RSA;

use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use Sop\JWX\JWK\Asymmetric\PrivateKeyJWK;
use Sop\JWX\JWK\Asymmetric\PublicKeyJWK;
use Sop\JWX\JWK\Parameter\ExponentParameter;
use Sop\JWX\JWK\Parameter\FirstCRTCoefficientParameter;
use Sop\JWX\JWK\Parameter\FirstFactorCRTExponentParameter;
use Sop\JWX\JWK\Parameter\FirstPrimeFactorParameter;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\KeyTypeParameter;
use Sop\JWX\JWK\Parameter\ModulusParameter;
use Sop\JWX\JWK\Parameter\PrivateExponentParameter;
use Sop\JWX\JWK\Parameter\SecondFactorCRTExponentParameter;
use Sop\JWX\JWK\Parameter\SecondPrimeFactorParameter;

/**
 * Class representing RSA private key as a JWK.
 *
 * @see https://tools.ietf.org/html/rfc7517#section-4
 * @see https://tools.ietf.org/html/rfc7518#section-6.3
 * @see https://tools.ietf.org/html/rfc7518#section-6.3.2
 */
class RSAPrivateKeyJWK extends PrivateKeyJWK
{
    /**
     * Parameter names managed by this class.
     *
     * @internal
     *
     * @var string[]
     */
    const MANAGED_PARAMS = [
        JWKParameter::PARAM_KEY_TYPE,
        JWKParameter::PARAM_MODULUS,
        JWKParameter::PARAM_EXPONENT,
        JWKParameter::PARAM_PRIVATE_EXPONENT,
        JWKParameter::PARAM_FIRST_PRIME_FACTOR,
        JWKParameter::PARAM_SECOND_PRIME_FACTOR,
        JWKParameter::PARAM_FIRST_FACTOR_CRT_EXPONENT,
        JWKParameter::PARAM_SECOND_FACTOR_CRT_EXPONENT,
        JWKParameter::PARAM_FIRST_CRT_COEFFICIENT,
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
        // cast private exponent to correct class
        $key = JWKParameter::PARAM_PRIVATE_EXPONENT;
        $this->_parameters[$key] = new PrivateExponentParameter(
            $this->_parameters[$key]->value());
    }

    /**
     * Initialize from RSAPrivateKey.
     *
     * @param RSAPrivateKey $pk
     *
     * @return self
     */
    public static function fromRSAPrivateKey(RSAPrivateKey $pk): self
    {
        $n = ModulusParameter::fromNumber($pk->modulus());
        $e = ExponentParameter::fromNumber($pk->publicExponent());
        $d = PrivateExponentParameter::fromNumber($pk->privateExponent());
        $p = FirstPrimeFactorParameter::fromNumber($pk->prime1());
        $q = SecondPrimeFactorParameter::fromNumber($pk->prime2());
        $dp = FirstFactorCRTExponentParameter::fromNumber($pk->exponent1());
        $dq = SecondFactorCRTExponentParameter::fromNumber($pk->exponent2());
        $qi = FirstCRTCoefficientParameter::fromNumber($pk->coefficient());
        $key_type = new KeyTypeParameter(KeyTypeParameter::TYPE_RSA);
        return new self($key_type, $n, $e, $d, $p, $q, $dp, $dq, $qi);
    }

    /**
     * Initialize from PEM.
     *
     * @param PEM $pem
     *
     * @return self
     */
    public static function fromPEM(PEM $pem): self
    {
        return self::fromRSAPrivateKey(RSAPrivateKey::fromPEM($pem));
    }

    /**
     * Get public key component.
     *
     * @return RSAPublicKeyJWK
     */
    public function publicKey(): PublicKeyJWK
    {
        $kty = $this->keyTypeParameter();
        $n = $this->modulusParameter();
        $e = $this->exponentParameter();
        return new RSAPublicKeyJWK($kty, $n, $e);
    }

    /**
     * Convert JWK to PEM.
     *
     * @return PEM
     */
    public function toPEM(): PEM
    {
        $n = $this->modulusParameter()->number()->base10();
        $e = $this->exponentParameter()->number()->base10();
        $d = $this->privateExponentParameter()->number()->base10();
        $p = $this->firstPrimeFactorParameter()->number()->base10();
        $q = $this->secondPrimeFactorParameter()->number()->base10();
        $dp = $this->firstFactorCRTExponentParameter()->number()->base10();
        $dq = $this->secondFactorCRTExponentParameter()->number()->base10();
        $qi = $this->firstCRTCoefficientParameter()->number()->base10();
        $pk = new RSAPrivateKey($n, $e, $d, $p, $q, $dp, $dq, $qi);
        return PrivateKeyInfo::fromPrivateKey($pk)->toPEM();
    }
}
