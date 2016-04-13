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
use CryptoUtil\ASN1\RSA\RSAPrivateKey;
use CryptoUtil\ASN1\PrivateKeyInfo;
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
	 * @param ModulusParameter $n
	 * @param ExponentParameter $e
	 * @param PrivateExponentParameter $d
	 * @param FirstPrimeFactorParameter $p
	 * @param SecondPrimeFactorParameter $q
	 * @param FirstFactorCRTExponentParameter $dp
	 * @param SecondFactorCRTExponentParameter $dq
	 * @param FirstCRTCoefficientParameter $qi
	 * @param JWKParameter ...$params Additional parameters
	 */
	public function __construct(ModulusParameter $n, ExponentParameter $e, 
		PrivateExponentParameter $d, FirstPrimeFactorParameter $p, 
		SecondPrimeFactorParameter $q, FirstFactorCRTExponentParameter $dp, 
		SecondFactorCRTExponentParameter $dq, FirstCRTCoefficientParameter $qi, 
		JWKParameter ...$params) {
		$params = array_merge($params, 
			array(new KeyTypeParameter(KeyTypeParameter::TYPE_RSA), $n, $e, $d, 
				$p, $q, $dp, $dq, $qi));
		parent::__construct(...$params);
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
		return new self($n, $e, $d, $p, $q, $dp, $dq, $qi);
	}
	
	public static function fromArray(array $members) {
		// check that all required parameters are present
		foreach (self::$_managedParams as $name) {
			if (!isset($members[$name])) {
				throw new \UnexpectedValueException("Missing '$name' parameter");
			}
		}
		// check that key type is RSA
		if ($members[RegisteredJWKParameter::PARAM_KEY_TYPE] !=
			 KeyTypeParameter::TYPE_RSA) {
			throw new \UnexpectedValueException("Not an RSA private key");
		}
		$params = array();
		foreach ($members as $name => $value) {
			$params[$name] = JWKParameter::fromNameAndValue($name, $value);
		}
		$n = $params[RegisteredJWKParameter::PARAM_MODULUS];
		$e = $params[RegisteredJWKParameter::PARAM_EXPONENT];
		$d = $params[RegisteredJWKParameter::PARAM_PRIVATE_EXPONENT];
		$p = $params[RegisteredJWKParameter::PARAM_FIRST_PRIME_FACTOR];
		$q = $params[RegisteredJWKParameter::PARAM_SECOND_PRIME_FACTOR];
		$dp = $params[RegisteredJWKParameter::PARAM_FIRST_FACTOR_CRT_EXPONENT];
		$dq = $params[RegisteredJWKParameter::PARAM_SECOND_FACTOR_CRT_EXPONENT];
		$qi = $params[RegisteredJWKParameter::PARAM_FIRST_CRT_COEFFICIENT];
		// remove managed parameters
		foreach (self::$_managedParams as $name) {
			unset($params[$name]);
		}
		return new self($n, $e, $d, $p, $q, $dp, $dq, $qi, ...$params);
	}
	
	/**
	 * Get public key component
	 *
	 * @return RSAPublicKeyJWK
	 */
	public function publicKey() {
		$n = $this->get(RegisteredJWKParameter::PARAM_MODULUS);
		$e = $this->get(RegisteredJWKParameter::PARAM_EXPONENT);
		return new RSAPublicKeyJWK($n, $e);
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
