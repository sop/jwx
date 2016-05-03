<?php

namespace JWX\JWE\KeyAlgorithm;

use AESKW\AESKW192;
use JWX\JWA\JWA;


/**
 * Implements AES key wrap with 192-bit key.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.4
 */
class A192KWAlgorithm extends AESKWAlgorithm
{
	protected function _AESKWAlgo() {
		return new AESKW192();
	}
	
	public function algorithmParamValue() {
		return JWA::ALGO_A192KW;
	}
}
