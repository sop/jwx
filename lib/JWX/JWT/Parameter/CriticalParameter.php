<?php

namespace JWX\JWT\Parameter;


/**
 * Critical parameter
 *
 * @link https://tools.ietf.org/html/rfc7515#section-4.1.11
 */
class CriticalParameter extends RegisteredJWTParameter
{
	/**
	 * Constructor
	 *
	 * @param string[] $names
	 */
	public function __construct(...$names) {
		parent::__construct(self::PARAM_CRITICAL, $names);
	}
	
	public static function fromJSONValue($value) {
		if (!is_array($value)) {
			throw new \UnexpectedValueException("Array expected");
		}
		return new static(...$value);
	}
}
