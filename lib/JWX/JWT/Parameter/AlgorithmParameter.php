<?php

namespace JWX\JWT\Parameter;

use JWX\JWT\AlgorithmParameterValue;


class AlgorithmParameter extends RegisteredJWTParameter
{
	public function __construct($value) {
		parent::__construct(self::PARAM_ALGORITHM, $value);
	}
	
	public static function fromAlgorithm(AlgorithmParameterValue $value) {
		return new self($value->algorithmParamValue());
	}
}
