<?php

namespace JWX\JWS\Algorithm;

use JWX\JWT\Parameter\AlgorithmParameter;


/**
 * RSASSA-PKCS1-v1_5 using SHA-256
 */
class RS256Algorithm extends RSAPKCS1Algorithm
{
	protected function _mdMethod() {
		return "sha256WithRSAEncryption";
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_RS256;
	}
}
