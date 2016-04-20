<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWA\JWA;
use AESKW\AESKW128;


class A128KWAlgorithm extends AESKWAlgorithm
{
	protected function _AESKWAlgo() {
		return new AESKW128();
	}
	
	public function algorithmParamValue() {
		return JWA::ALGO_A128KW;
	}
}
