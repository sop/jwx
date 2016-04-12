<?php

namespace JWX\JWT\Parameter;

use JWX\JWT\AlgorithmParameterValue;


class EncryptionAlgorithmParameter extends RegisteredJWTParameter
{
	public function __construct($value) {
		parent::__construct(self::PARAM_ENCRYPTION_ALGORITHM, $value);
	}
	
	public static function fromAlgorithm(AlgorithmParameterValue $value) {
		return new self($value->algorithmParamValue());
	}
}
