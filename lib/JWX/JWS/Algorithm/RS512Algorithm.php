<?php

namespace JWX\JWS\Algorithm;

use JWX\JWT\Parameter\AlgorithmParameter;


/**
 * RSASSA-PKCS1-v1_5 using SHA-512
 */
class RS512Algorithm extends RSAPKCS1Algorithm
{
	protected function _mdMethod() {
		return "sha512WithRSAEncryption";
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_RS512;
	}
}
