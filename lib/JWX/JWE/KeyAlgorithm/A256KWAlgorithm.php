<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWA\JWA;
use AESKW\AESKW256;


class A256KWAlgorithm extends AESKWAlgorithm
{
	protected function _AESKWAlgo() {
		return new AESKW256();
	}
	
	public function algorithmParamValue() {
		return JWA::ALGO_A256KW;
	}
}
