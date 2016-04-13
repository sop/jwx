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


class RSAPrivateKeyJWK extends JWK
{
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
		$params = array_merge(
			array(new KeyTypeParameter(KeyTypeParameter::TYPE_RSA), $n, $e, $d, 
				$p, $q, $dp, $dq, $qi), $params);
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
	
	/**
	 * Convert JWK to PEM
	 *
	 * @return PEM
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
		return $pk->toPEM();
	}
}
