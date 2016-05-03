<?php

namespace JWX\JWK\Parameter;


/**
 * Implements 'Curve' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-6.2.1.1
 */
class CurveParameter extends RegisteredJWKParameter
{
	const CURVE_P256 = "P-256";
	const CURVE_P384 = "P-384";
	const CURVE_P521 = "P-521";
	
	/**
	 * Constructor
	 *
	 * @param string $curve Curve name
	 */
	public function __construct($curve) {
		parent::__construct(self::PARAM_CURVE, $curve);
	}
}
