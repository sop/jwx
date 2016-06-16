<?php

namespace JWX\JWS;

use JWX\JWK\JWK;
use JWX\JWS\Algorithm\SignatureAlgorithmFactory;
use JWX\JWT\Header\Header;
use JWX\JWT\Header\HeaderParameters;
use JWX\JWT\Parameter\AlgorithmParameterValue;


/**
 * Base class for algorithms usable for signing and validating JWS's.
 */
abstract class SignatureAlgorithm implements 
	AlgorithmParameterValue, 
	HeaderParameters
{
	/**
	 * Compute signature.
	 *
	 * @param string $data Data for which the signature is computed
	 * @return string
	 */
	abstract public function computeSignature($data);
	
	/**
	 * Validate signature.
	 *
	 * @param string $data Data to validate
	 * @param string $signature Signature to compare
	 * @return bool
	 */
	abstract public function validateSignature($data, $signature);
	
	/**
	 * Initialize signature algorithm from a JWK and a header.
	 *
	 * @param JWK $jwk JSON Web Key
	 * @param Header $header Header
	 * @return SignatureAlgorithm
	 */
	public static function fromJWK(JWK $jwk, Header $header) {
		$factory = new SignatureAlgorithmFactory($header);
		return $factory->algoByKey($jwk);
	}
}
