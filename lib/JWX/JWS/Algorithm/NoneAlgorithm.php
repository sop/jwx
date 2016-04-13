<?php

namespace JWX\JWS\Algorithm;

use JWX\JWS\SignatureAlgorithm;
use JWX\JWT\Parameter\AlgorithmParameter;


class NoneAlgorithm implements SignatureAlgorithm
{
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_NONE;
	}
	
	public function computeSignature($data) {
		return "";
	}
	
	public function validateSignature($data, $signature) {
		return $signature === "";
	}
}
