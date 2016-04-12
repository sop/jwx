<?php

namespace JWX\JWT\Parameter;

use JWX\JWT\AlgorithmParameterValue;


class AlgorithmParameter extends RegisteredParameter
{
	public function __construct($value) {
		parent::__construct(self::NAME_ALGORITHM, $value);
	}
	
	public static function fromAlgorithm(AlgorithmParameterValue $value) {
		return new self($value->algorithmParamValue());
	}
}
