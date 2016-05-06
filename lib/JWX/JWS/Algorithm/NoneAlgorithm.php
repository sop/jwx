<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;
use JWX\JWS\SignatureAlgorithm;
use JWX\JWT\Parameter\AlgorithmParameter;


/**
 * Algorithm for unsecured JWS/JWT.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.6
 * @link https://tools.ietf.org/html/rfc7519#section-6
 */
class NoneAlgorithm implements SignatureAlgorithm
{
	public function algorithmParamValue() {
		return JWA::ALGO_NONE;
	}
	
	public function computeSignature($data) {
		return "";
	}
	
	public function validateSignature($data, $signature) {
		return $signature === "";
	}
	
	public function headerParameters() {
		return array(AlgorithmParameter::fromAlgorithm($this));
	}
}
