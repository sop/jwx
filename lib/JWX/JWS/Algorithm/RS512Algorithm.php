<?php

namespace JWX\JWS\Algorithm;

use JWX\JWT\Parameter\AlgorithmParameter;


class RS512Algorithm extends RSAPKCS1Algorithm
{
	protected function _mdMethod() {
		return "sha512WithRSAEncryption";
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_RS512;
	}
}
