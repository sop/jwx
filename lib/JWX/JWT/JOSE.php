<?php

namespace JWX\JWT;

use JWX\JWT\Parameter\RegisteredJWTParameter;


class JOSE extends Header
{
	/**
	 * Constructor
	 *
	 * @param Header ...$headers One or more headers to merge
	 */
	public function __construct(Header ...$headers) {
		$params = array();
		foreach ($headers as $header) {
			foreach ($header->parameters() as $param) {
				if (isset($params[$param->name()])) {
					throw new \UnexpectedValueException("Duplicate parameter");
				}
				$params[$param->name()] = $param;
			}
		}
		parent::__construct(...array_values($params));
	}
	
	/**
	 * Whether JOSE is for JWS
	 *
	 * @return bool
	 */
	public function isJWS() {
		return $this->has(RegisteredJWTParameter::PARAM_ALGORITHM) &&
			 !$this->has(RegisteredJWTParameter::PARAM_ENCRYPTION_ALGORITHM);
	}
	
	/**
	 * Whether JOSE is for JWE
	 *
	 * @return bool
	 */
	public function isJWE() {
		return $this->has(RegisteredJWTParameter::PARAM_ENCRYPTION_ALGORITHM);
	}
}
