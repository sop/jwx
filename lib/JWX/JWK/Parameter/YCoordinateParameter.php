<?php

namespace JWX\JWK\Parameter;


class YCoordinateParameter extends RegisteredJWKParameter
{
	/**
	 * Constructor
	 *
	 * @param string $coord Y coordinate in base64url encoding
	 */
	public function __construct($coord) {
		parent::__construct(self::PARAM_Y_COORDINATE, $coord);
	}
}
