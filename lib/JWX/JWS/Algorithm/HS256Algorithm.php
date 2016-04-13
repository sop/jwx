<?php

namespace JWX\JWS\Algorithm;

use JWX\JWT\Parameter\AlgorithmParameter;


class HS256Algorithm extends HMACAlgorithm
{
	protected function _hashAlgo() {
		return "sha256";
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_HS256;
	}
}
