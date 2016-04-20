<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;


/**
 * RSASSA-PKCS1-v1_5 using SHA-384
 */
class RS384Algorithm extends RSASSAPKCS1Algorithm
{
	protected function _mdMethod() {
		return "sha384WithRSAEncryption";
	}
	
	public function algorithmParamValue() {
		return JWA::ALGO_RS384;
	}
}
