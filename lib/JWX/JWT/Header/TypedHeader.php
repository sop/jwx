<?php

namespace JWX\JWT\Header;

use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\AuthenticationTagParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;


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
	 *
	 * @return bool
	 */
	public function hasAlgorithm() {
		return $this->has(RegisteredJWTParameter::P_ALG);
	}
	
	/**
	 *
	 * @throws \UnexpectedValueException
	 * @return AlgorithmParameter
	 */
	public function algorithm() {
		$param = $this->get(RegisteredJWTParameter::P_ALG);
		if (!$param instanceof AlgorithmParameter) {
			throw new \UnexpectedValueException();
		}
		return $param;
	}
	
	/**
	 *
	 * @return bool
	 */
	public function hasAuthenticationTag() {
		return $this->has(RegisteredJWTParameter::P_TAG);
	}
	
	/**
	 *
	 * @throws \UnexpectedValueException
	 * @return AuthenticationTagParameter
	 */
	public function authenticationTag() {
		$param = $this->get(RegisteredJWTParameter::P_TAG);
		if (!$param instanceof AuthenticationTagParameter) {
			throw new \UnexpectedValueException();
		}
		return $param;
	}
}
