<?php

namespace JWX\JWK\Parameter;

use JWX\Util\Base64;


class KeyValueParameter extends RegisteredJWKParameter
{
	/**
	 * Constructor
	 *
	 * @param string $key Base64url encoded key
	 */
	public function __construct($key) {
		parent::__construct(self::PARAM_KEY_VALUE, $key);
	}
	
	/**
	 * Initialize from binary key
	 *
	 * @param string $key
	 * @return self
	 */
	public static function fromKey($key) {
		return new self(Base64::urlEncode($key));
	}
	
	/**
	 * Get key in binary format
	 *
	 * @return string
	 */
	public function key() {
		return Base64::urlDecode($this->_value);
	}
}
