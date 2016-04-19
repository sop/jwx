<?php

namespace JWX\JWK\RSA;

use JWX\JWK\JWK;
use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\KeyTypeParameter;
use JWX\JWK\Parameter\ModulusParameter;
use JWX\JWK\Parameter\ExponentParameter;
use JWX\JWK\Parameter\PrivateExponentParameter;
use JWX\JWK\Parameter\FirstPrimeFactorParameter;
use JWX\JWK\Parameter\SecondPrimeFactorParameter;
use JWX\JWK\Parameter\FirstFactorCRTExponentParameter;
use JWX\JWK\Parameter\SecondFactorCRTExponentParameter;
use JWX\JWK\Parameter\FirstCRTCoefficientParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;
use CryptoUtil\PEM\PEM;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\ASN1\RSA\RSAPrivateKey;
use CryptoUtil\ASN1\RSA\RSAEncryptionAlgorithmIdentifier;


class RSAPrivateKeyJWK extends JWK
{
	/**
	 * Parameter names managed by this class
	 *
	 * @var string[]
	 */
	private static $_managedParams = array(
		RegisteredJWKParameter::PARAM_KEY_TYPE, 
		RegisteredJWKParameter::PARAM_MODULUS, 
		RegisteredJWKParameter::PARAM_EXPONENT, 
		RegisteredJWKParameter::PARAM_PRIVATE_EXPONENT, 
		RegisteredJWKParameter::PARAM_FIRST_PRIME_FACTOR, 
		RegisteredJWKParameter::PARAM_SECOND_PRIME_FACTOR, 
		RegisteredJWKParameter::PARAM_FIRST_FACTOR_CRT_EXPONENT, 
		RegisteredJWKParameter::PARAM_SECOND_FACTOR_CRT_EXPONENT, 
		RegisteredJWKParameter::PARAM_FIRST_CRT_COEFFICIENT);
	
	/**
	 * Constructor
	 *
	 * @param JWKParameter ...$params
	 * @throws \UnexpectedValueException If missing required parameter
	 */
	public function __construct(JWKParameter ...$params) {
		parent::__construct(...$params);
		foreach (self::$_managedParams as $name) {
			if (!$this->has($name)) {
				throw new \UnexpectedValueException("Missing '$name' parameter");
			}
		}
		if ($this->get(RegisteredJWKParameter::PARAM_KEY_TYPE)->value() !=
			 KeyTypeParameter::TYPE_RSA) {
			throw new \UnexpectedValueException("Invalid key type");
		}
	}
	
	/**
	 * Initialize from PEM
	 *
	 * @param PEM $pem
	 * @return self
	 */
	public static function fromPEM(PEM $pem) {
		$pk = RSAPrivateKey::fromPEM($pem);
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
	 * Get public key component
	 *
	 * @return RSAPublicKeyJWK
	 */
	public function publicKey() {
		$kty = $this->get(RegisteredJWKParameter::PARAM_KEY_TYPE);
		$n = $this->get(RegisteredJWKParameter::PARAM_MODULUS);
		$e = $this->get(RegisteredJWKParameter::PARAM_EXPONENT);
		return new RSAPublicKeyJWK($kty, $n, $e);
	}
	
	/**
	 * Convert JWK to PEM
	 *
	 * @return PEM PRIVATE KEY
	 */
	public function toPEM() {
		$n = $this->get(RegisteredJWKParameter::PARAM_MODULUS)
			->number()
			->base10();
		$e = $this->get(RegisteredJWKParameter::PARAM_EXPONENT)
			->number()
			->base10();
		$d = $this->get(RegisteredJWKParameter::PARAM_PRIVATE_EXPONENT)
			->number()
			->base10();
		$p = $this->get(RegisteredJWKParameter::PARAM_FIRST_PRIME_FACTOR)
			->number()
			->base10();
		$q = $this->get(RegisteredJWKParameter::PARAM_SECOND_PRIME_FACTOR)
			->number()
			->base10();
		$dp = $this->get(
			RegisteredJWKParameter::PARAM_FIRST_FACTOR_CRT_EXPONENT)
			->number()
			->base10();
		$dq = $this->get(
			RegisteredJWKParameter::PARAM_SECOND_FACTOR_CRT_EXPONENT)
			->number()
			->base10();
		$qi = $this->get(RegisteredJWKParameter::PARAM_FIRST_CRT_COEFFICIENT)
			->number()
			->base10();
		$pk = new RSAPrivateKey($n, $e, $d, $p, $q, $dp, $dq, $qi);
		$pki = new PrivateKeyInfo(new RSAEncryptionAlgorithmIdentifier(), 
			$pk->toDER());
		return $pki->toPEM();
	}
}
