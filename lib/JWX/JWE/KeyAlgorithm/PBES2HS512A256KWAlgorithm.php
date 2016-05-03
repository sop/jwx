<?php

namespace JWX\JWE\KeyAlgorithm;

use AESKW\AESKW256;
use JWX\JWA\JWA;


/**
 * Implements PBES2 with HMAC SHA-512 and "A256KW" wrapping.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.8
 */
class PBES2HS512A256KWAlgorithm extends PBES2Algorithm
{
	protected function _hashAlgo() {
		return "sha512";
	}
	
	protected function _keyLength() {
		return 32;
	}
	
	protected function _kwAlgo() {
		return new AESKW256();
	}
	
	public function algorithmParamValue() {
		return JWA::ALGO_PBES2_HS512_A256KW;
	}
}
