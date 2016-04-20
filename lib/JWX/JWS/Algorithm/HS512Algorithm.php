<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;


/**
 * HMAC using SHA-512
 */
class HS512Algorithm extends HMACAlgorithm
{
	protected function _hashAlgo() {
		return "sha512";
	}
	
	public function algorithmParamValue() {
		return JWA::ALGO_HS512;
	}
}
