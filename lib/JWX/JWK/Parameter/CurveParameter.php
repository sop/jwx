<?php

namespace JWX\JWK\Parameter;


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
