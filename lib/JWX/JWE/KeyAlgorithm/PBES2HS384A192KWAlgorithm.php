<?php

namespace JWX\JWE\KeyAlgorithm;

use AESKW\AESKW192;
use JWX\JWA\JWA;


/**
 * Implements PBES2 with HMAC SHA-384 and "A192KW" wrapping.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.8
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
		return JWA::ALGO_PBES2_HS384_A192KW;
	}
}
