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
}
