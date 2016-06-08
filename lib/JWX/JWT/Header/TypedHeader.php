<?php

namespace JWX\JWT\Header;

use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\AuthenticationTagParameter;
use JWX\JWT\Parameter\B64PayloadParameter;
use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;


/**
 * Trait for Header to provide parameter accessor methods for typed return
 * types.
 */
trait TypedHeader
{
	/**
	 * Whether parameters are present.
	 *
	 * @param string ...$names Parameter names
	 * @return bool
	 */
	abstract public function has(...$names);
	
	/**
	 * Get a parameter.
	 *
	 * @param string $name Parameter name
	 * @return JWTParameter
	 */
	abstract public function get($name);
	
	/**
	 * Check whether the algorithm parameter is present.
	 *
	 * @return bool
	 */
	public function hasAlgorithm() {
		return $this->has(RegisteredJWTParameter::P_ALG);
	}
	
	/**
	 * Get the algorithm parameter.
	 *
	 * @throws \UnexpectedValueException
	 * @return AlgorithmParameter
	 */
	public function algorithm() {
		return $this->_checkType($this->get(RegisteredJWTParameter::P_ALG), 
			AlgorithmParameter::class);
	}
	
	/**
	 * Check whether the authentication tag parameter is present.
	 *
	 * @return bool
	 */
	public function hasAuthenticationTag() {
		return $this->has(RegisteredJWTParameter::P_TAG);
	}
	
	/**
	 * Get the authentication tag parameter.
	 *
	 * @throws \UnexpectedValueException
	 * @return AuthenticationTagParameter
	 */
	public function authenticationTag() {
		return $this->_checkType($this->get(RegisteredJWTParameter::P_TAG), 
			AuthenticationTagParameter::class);
	}
	
	/**
	 * Check whether the 'base64url-encode payload' parameter is present.
	 *
	 * @return bool
	 */
	public function hasB64Payload() {
		return $this->has(RegisteredJWTParameter::P_B64);
	}
	
	/**
	 * Get the 'base64url-encode payload' parameter.
	 *
	 * @throws \UnexpectedValueException
	 * @return B64PayloadParameter
	 */
	public function b64Payload() {
		return $this->_checkType($this->get(RegisteredJWTParameter::P_B64), 
			B64PayloadParameter::class);
	}
	
	/**
	 *
	 * @param JWTParameter $param
	 * @param string $cls
	 * @throws \UnexpectedValueException
	 * @return JWTParameter
	 */
	private static function _checkType(JWTParameter $param, $cls) {
		if (!$param instanceof $cls) {
			throw new \UnexpectedValueException(
				"$cls expected, got " . get_class($param));
		}
		return $param;
	}
}
