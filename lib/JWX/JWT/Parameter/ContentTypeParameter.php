<?php

namespace JWX\JWT\Parameter;

use JWX\Parameter\Feature\StringParameterValue;


/**
 * Implements 'Content Type' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7515#section-4.1.10
 */
class ContentTypeParameter extends JWTParameter
{
	use StringParameterValue;
	
	/**
	 * Content type for the nested JWT.
	 *
	 * @var string
	 */
	const TYPE_JWT = "JWT";
	
	/**
	 * Constructor
	 *
	 * @param string $type
	 */
	public function __construct($type) {
		parent::__construct(self::PARAM_CONTENT_TYPE, (string) $type);
	}
}
