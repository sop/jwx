<?php

namespace JWX\JWS\Algorithm;

use JWX\JWT\Parameter\AlgorithmParameter;


class HS384Algorithm extends HMACAlgorithm
{
	protected function _hashAlgo() {
		return "sha384";
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_HS384;
	}
}
