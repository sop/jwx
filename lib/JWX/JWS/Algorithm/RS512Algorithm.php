<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;


/**
 * RSASSA-PKCS1-v1_5 using SHA-512
 */
class RS512Algorithm extends RSASSAPKCS1Algorithm
{
	protected function _mdMethod() {
		return "sha512WithRSAEncryption";
	}
	
	public function algorithmParamValue() {
		return JWA::ALGO_RS512;
	}
}
