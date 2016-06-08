<?php

namespace JWX\JWK\RSA;

use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\RSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\ASN1\RSA\RSAPrivateKey;
use CryptoUtil\PEM\PEM;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\ExponentParameter;
use JWX\JWK\Parameter\FirstCRTCoefficientParameter;
use JWX\JWK\Parameter\FirstFactorCRTExponentParameter;
use JWX\JWK\Parameter\FirstPrimeFactorParameter;
use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\KeyTypeParameter;
use JWX\JWK\Parameter\ModulusParameter;
use JWX\JWK\Parameter\PrivateExponentParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;
use JWX\JWK\Parameter\SecondFactorCRTExponentParameter;
use JWX\JWK\Parameter\SecondPrimeFactorParameter;


/**
 * Class representing RSA private key as a JWK.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4
 * @link https://tools.ietf.org/html/rfc7518#section-6.3
 * @link https://tools.ietf.org/html/rfc7518#section-6.3.2
 */
class RSAPrivateKeyJWK extends JWK
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
		RegisteredJWKParameter::PARAM_KEY_TYPE,
		RegisteredJWKParameter::PARAM_MODULUS,
		RegisteredJWKParameter::PARAM_EXPONENT,
		RegisteredJWKParameter::PARAM_PRIVATE_EXPONENT,
		RegisteredJWKParameter::PARAM_FIRST_PRIME_FACTOR,
		RegisteredJWKParameter::PARAM_SECOND_PRIME_FACTOR,
		RegisteredJWKParameter::PARAM_FIRST_FACTOR_CRT_EXPONENT,
		RegisteredJWKParameter::PARAM_SECOND_FACTOR_CRT_EXPONENT,
		RegisteredJWKParameter::PARAM_FIRST_CRT_COEFFICIENT
		/* @formatter:on */
	);
	
	/**
	 * Constructor
	 *
	 * @param JWKParameter ...$params
	 * @throws \UnexpectedValueException If missing required parameter
	 */
	public function __construct(JWKParameter ...$params) {
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
	 * Initialize from RSAPrivateKey.
	 *
	 * @param RSAPrivateKey $pk
	 * @return self
	 */
	public static function fromRSAPrivateKey(RSAPrivateKey $pk) {
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
	 * @return self
	 */
	public static function fromPEM(PEM $pem) {
		return self::fromRSAPrivateKey(RSAPrivateKey::fromPEM($pem));
	}
	
	/**
	 * Get public key component.
	 *
	 * @return RSAPublicKeyJWK
	 */
	public function publicKey() {
		$kty = $this->keyTypeParameter();
		$n = $this->modulusParameter();
		$e = $this->exponentParameter();
		return new RSAPublicKeyJWK($kty, $n, $e);
	}
	
	/**
	 * Convert JWK to PEM.
	 *
	 * @return PEM PRIVATE KEY
	 */
	public function toPEM() {
		$n = $this->modulusParameter()
			->number()
			->base10();
		$e = $this->exponentParameter()
			->number()
			->base10();
		$d = $this->privateExponentParameter()
			->number()
			->base10();
		$p = $this->firstPrimeFactorParameter()
			->number()
			->base10();
		$q = $this->secondPrimeFactorParameter()
			->number()
			->base10();
		$dp = $this->firstFactorCRTExponentParameter()
			->number()
			->base10();
		$dq = $this->secondFactorCRTExponentParameter()
			->number()
			->base10();
		$qi = $this->firstCRTCoefficientParameter()
			->number()
			->base10();
		$pk = new RSAPrivateKey($n, $e, $d, $p, $q, $dp, $dq, $qi);
		$pki = new PrivateKeyInfo(new RSAEncryptionAlgorithmIdentifier(), 
			$pk->toDER());
		return $pki->toPEM();
	}
}
