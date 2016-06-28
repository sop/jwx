<?php

namespace JWX\JWK\Parameter;

use JWX\Parameter\Feature\Base64URLValue;


/**
 * Implements 'Key Value' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-6.4.1
 */
class KeyValueParameter extends JWKParameter
{
	use Base64URLValue;
	
	/**
	 * Constructor
	 *
	 * @param string $key Base64url encoded key
	 */
	public function __construct($key) {
		$this->_validateEncoding($key);
		parent::__construct(self::PARAM_KEY_VALUE, $key);
	}
	
	/**
	 * Get key in binary format.
	 *
	 * @return string
	 */
	public function key() {
		return $this->string();
	}
}
