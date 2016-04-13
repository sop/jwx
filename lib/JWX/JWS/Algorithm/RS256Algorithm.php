<?php

namespace JWX\JWS\Algorithm;

use JWX\JWT\Parameter\AlgorithmParameter;


class RS256Algorithm extends RSAPKCS1Algorithm
{
	protected function _mdMethod() {
		return "sha256WithRSAEncryption";
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_RS256;
	}
}
