<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWT\Parameter\AlgorithmParameter;
use AESKW\AESKW128;


/**
 * PBES2 with HMAC SHA-256 and "A128KW" wrapping
 */
class PBES2HS256A128KWAlgorithm extends PBES2Algorithm
{
	protected function _hashAlgo() {
		return "sha256";
	}
	
	protected function _keyLength() {
		return 16;
	}
	
	protected function _kwAlgo() {
		return new AESKW128();
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_PBES2_HS256_A128KW;
	}
}
