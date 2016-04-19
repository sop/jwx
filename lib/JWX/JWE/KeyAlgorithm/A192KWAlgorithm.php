<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWT\Parameter\AlgorithmParameter;
use AESKW\AESKW192;


class A192KWAlgorithm extends AESKWAlgorithm
{
	protected function _AESKWAlgo() {
		return new AESKW192();
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_A192KW;
	}
}
