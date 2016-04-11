<?php

namespace JWX\JWK\Parameter;


class XCoordinateParameter extends RegisteredJWKParameter
{
	/**
	 * Constructor
	 *
	 * @param string $coord X coordinate in base64url encoding
	 */
	public function __construct($coord) {
		parent::__construct(self::PARAM_X_COORDINATE, $coord);
	}
}
