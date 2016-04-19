<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWT\Parameter\AlgorithmParameter;
use AESKW\AESKW128;


class A128KWAlgorithm extends AESKWAlgorithm
{
	protected function _AESKWAlgo() {
		return new AESKW128();
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_A128KW;
	}
}
