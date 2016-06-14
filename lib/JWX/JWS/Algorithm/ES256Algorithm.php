<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;
use JWX\JWK\Parameter\CurveParameter;


/**
 * Implements ECDSA using P-256 and SHA-256.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.4
 */
class ES256Algorithm extends ECDSAAlgorithm
{
	protected function _curveName() {
		return CurveParameter::CURVE_P256;
	}
	
	protected function _mdMethod() {
		return "sha256";
	}
	
	public function algorithmParamValue() {
		return JWA::ALGO_ES256;
	}
}
