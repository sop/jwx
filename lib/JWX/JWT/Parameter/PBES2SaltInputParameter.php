<?php

namespace JWX\JWT\Parameter;

use JWX\JWT\Parameter\Feature\Base64URLValue;
use JWX\Util\Base64;


/**
 * Implements 'PBES2 Salt Input' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.8.1.1
 */
class PBES2SaltInputParameter extends RegisteredJWTParameter
{
	use Base64URLValue;
	
	/**
	 * Constructor
	 *
	 * @param string $salt Base64url encoded salt input value
	 */
	public function __construct($salt) {
		parent::__construct(self::PARAM_PBES2_SALT_INPUT, (string) $salt);
	}
	
	/**
	 * Get salt input value.
	 *
	 * @return string
	 */
	public function saltInput() {
		return Base64::urlDecode($this->_value);
	}
	
	/**
	 * Get computed salt value.
	 *
	 * @param AlgorithmParameter $algo
	 * @return string
	 */
	public function salt(AlgorithmParameter $algo) {
		return $algo->value() . "\0" . $this->saltInput();
	}
}
