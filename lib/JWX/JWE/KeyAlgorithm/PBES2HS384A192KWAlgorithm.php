<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWT\Parameter\AlgorithmParameter;
use AESKW\AESKW192;


/**
 * PBES2 with HMAC SHA-384 and "A192KW" wrapping
 */
class PBES2HS384A192KWAlgorithm extends PBES2Algorithm
{
	protected function _hashAlgo() {
		return "sha384";
	}
	
	protected function _keyLength() {
		return 24;
	}
	
	protected function _kwAlgo() {
		return new AESKW192();
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_PBES2_HS384_A192KW;
	}
}
