<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;


/**
 * HMAC using SHA-256
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
