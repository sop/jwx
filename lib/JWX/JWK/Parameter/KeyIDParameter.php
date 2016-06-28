<?php

namespace JWX\JWK\Parameter;

use JWX\Parameter\Feature\StringParameterValue;


/**
 * Implements 'Key ID' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4.5
 */
class KeyIDParameter extends JWKParameter
{
	use StringParameterValue;
	
	/**
	 * Constructor
	 *
	 * @param string $id Key ID
	 */
	public function __construct($id) {
		parent::__construct(self::PARAM_KEY_ID, $id);
	}
}
