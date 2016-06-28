<?php

namespace JWX\JWT\Parameter;

use JWX\Parameter\Feature\Base64URLValue;


/**
 * Implements 'Initialization Vector' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.7.1.1
 */
class InitializationVectorParameter extends JWTParameter
{
	use Base64URLValue;
	
	/**
	 * Constructor
	 *
	 * @param string $iv Base64url encoded initialization vector
	 */
	public function __construct($iv) {
		$this->_validateEncoding($iv);
		parent::__construct(self::PARAM_INITIALIZATION_VECTOR, (string) $iv);
	}
	
	/**
	 * Get the initialization vector.
	 *
	 * @return string
	 */
	public function initializationVector() {
		return $this->string();
	}
}
