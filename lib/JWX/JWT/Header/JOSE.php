<?php

namespace JWX\JWT\Header;

use JWX\JWT\Parameter\RegisteredJWTParameter;


/**
 * Represents as JOSE header.
 *
 * JOSE header consists of one or more Header objects, that are merged together.
 *
 * @link https://tools.ietf.org/html/rfc7519#section-5
 * @link https://tools.ietf.org/html/rfc7515#section-4
 * @link https://tools.ietf.org/html/rfc7516#section-4
 */
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
					throw new \UnexpectedValueException("Duplicate parameter.");
				}
				$params[$param->name()] = $param;
			}
		}
		parent::__construct(...array_values($params));
	}
	
	/**
	 * Get self merged with another Header.
	 *
	 * @param Header $header
	 * @return self
	 */
	public function withHeader(Header $header) {
		return new self($this, $header);
	}
	
	/**
	 * Whether JOSE is for a JWS.
	 *
	 * @return bool
	 */
	public function isJWS() {
		return $this->has(RegisteredJWTParameter::PARAM_ALGORITHM) &&
			 !$this->has(RegisteredJWTParameter::PARAM_ENCRYPTION_ALGORITHM);
	}
	
	/**
	 * Whether JOSE is for a JWE.
	 *
	 * @return bool
	 */
	public function isJWE() {
		return $this->has(RegisteredJWTParameter::PARAM_ENCRYPTION_ALGORITHM);
	}
}
