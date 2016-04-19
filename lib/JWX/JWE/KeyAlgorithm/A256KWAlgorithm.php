<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWT\Parameter\AlgorithmParameter;
use AESKW\AESKW256;


class A256KWAlgorithm extends AESKWAlgorithm
{
	protected function _AESKWAlgo() {
		return new AESKW256();
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_A256KW;
	}
}
