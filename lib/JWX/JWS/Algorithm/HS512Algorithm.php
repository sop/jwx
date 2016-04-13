<?php

namespace JWX\JWS\Algorithm;

use JWX\JWT\Parameter\AlgorithmParameter;


class HS512Algorithm extends HMACAlgorithm
{
	protected function _hashAlgo() {
		return "sha512";
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_HS512;
	}
}
