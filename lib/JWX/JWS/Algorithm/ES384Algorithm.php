<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;
use JWX\JWK\Parameter\CurveParameter;


/**
 * Implements ECDSA using P-384 and SHA-384.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.4
 */
class ES384Algorithm extends ECDSAAlgorithm
{
	protected function _curveName() {
		return CurveParameter::CURVE_P384;
	}
	
	protected function _mdMethod() {
		return "sha384";
	}
	
	public function algorithmParamValue() {
		return JWA::ALGO_ES384;
	}
}
