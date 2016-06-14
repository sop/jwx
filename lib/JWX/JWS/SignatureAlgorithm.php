<?php

namespace JWX\JWS;

use JWX\JWT\Header\HeaderParameters;
use JWX\JWT\Parameter\AlgorithmParameterValue;


/**
 * Interface for algorithms usable for signing and validating JWS's.
 */
interface SignatureAlgorithm extends AlgorithmParameterValue, HeaderParameters
{
	/**
	 * Compute signature.
	 *
	 * @param string $data Data for which the signature is computed
	 * @return string
	 */
	public function computeSignature($data);
	
	/**
	 * Validate signature.
	 *
	 * @param string $data Data to validate
	 * @param string $signature Signature to compare
	 * @return bool
	 */
	public function validateSignature($data, $signature);
}
