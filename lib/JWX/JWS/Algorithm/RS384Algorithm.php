<?php

namespace JWX\JWS\Algorithm;

use JWX\JWT\Parameter\AlgorithmParameter;


/**
 * RSASSA-PKCS1-v1_5 using SHA-384
 */
class RS384Algorithm extends RSAPKCS1Algorithm
{
	protected function _mdMethod() {
		return "sha384WithRSAEncryption";
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_RS384;
	}
}
