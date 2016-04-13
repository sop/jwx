<?php

namespace JWX\JWK\RSA;

use JWX\JWK\JWK;
use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\KeyTypeParameter;
use JWX\JWK\Parameter\ModulusParameter;
use JWX\JWK\Parameter\ExponentParameter;
use CryptoUtil\PEM\PEM;
use CryptoUtil\ASN1\RSA\RSAPublicKey;


class RSAPublicKeyJWK extends JWK
{
	/**
	 * Constructor
	 *
	 * @param ModulusParameter $n
	 * @param ExponentParameter $e
	 * @param JWKParameter ...$params Additional parameters
	 */
	public function __construct(ModulusParameter $n, ExponentParameter $e, 
		JWKParameter ...$params) {
		$params = array_merge(
			array(new KeyTypeParameter(KeyTypeParameter::TYPE_RSA), $n, $e), 
			$params);
		parent::__construct(...$params);
	}
	
	/**
	 * Initialize from PEM
	 *
	 * @param PEM $pem
	 * @return self
	 */
	public static function fromPEM(PEM $pem) {
		$pk = RSAPublicKey::fromPEM($pem);
		$n = ModulusParameter::fromNumber($pk->modulus());
		$e = ExponentParameter::fromNumber($pk->publicExponent());
		return new self($n, $e);
	}
}
