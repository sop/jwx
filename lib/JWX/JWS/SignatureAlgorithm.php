<?php

namespace JWX\JWS;

use JWX\JWT\AlgorithmParameterValue;


interface SignatureAlgorithm extends AlgorithmParameterValue
{
	/**
	 * Compute signature
	 *
	 * @param string $data Data for which the signature is computed
	 * @return string
	 */
	public function computeSignature($data);
	
	/**
	 * Validate signature
	 *
	 * @param string $data Data to validate
	 * @param string $signature Signature to compare
	 * @return boolean
	 */
	public function validateSignature($data, $signature);
}
