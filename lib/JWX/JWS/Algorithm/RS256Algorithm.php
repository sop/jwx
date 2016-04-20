<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;


/**
 * RSASSA-PKCS1-v1_5 using SHA-256
 */
class RS256Algorithm extends RSASSAPKCS1Algorithm
{
	protected function _mdMethod() {
		return "sha256WithRSAEncryption";
	}
	
	public function algorithmParamValue() {
		return JWA::ALGO_RS256;
	}
}
