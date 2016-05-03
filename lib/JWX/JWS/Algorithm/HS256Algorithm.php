<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;


/**
 * Implements HMAC using SHA-256.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.2
 */
class HS256Algorithm extends HMACAlgorithm
{
	protected function _hashAlgo() {
		return "sha256";
	}
	
	public function algorithmParamValue() {
		return JWA::ALGO_HS256;
	}
}
