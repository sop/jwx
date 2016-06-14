<?php

namespace JWX\JWK\Parameter;


/**
 * Implements 'X Coordinate' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-6.2.1.2
 */
class XCoordinateParameter extends CoordinateParameter
{
	/**
	 * Constructor
	 *
	 * @param string $coord X coordinate in base64url encoding
	 */
	public function __construct($coord) {
		$this->_validateEncoding($coord);
		parent::__construct(self::PARAM_X_COORDINATE, $coord);
	}
}
