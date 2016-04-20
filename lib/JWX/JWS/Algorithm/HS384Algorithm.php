<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;


/**
 * HMAC using SHA-384
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
