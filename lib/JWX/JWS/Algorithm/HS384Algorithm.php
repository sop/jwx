<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;


/**
 * Implements HMAC using SHA-384.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.2
 */
class HS384Algorithm extends HMACAlgorithm
{
	protected function _hashAlgo() {
		return "sha384";
	}
	
	public function algorithmParamValue() {
		return JWA::ALGO_HS384;
	}
}
