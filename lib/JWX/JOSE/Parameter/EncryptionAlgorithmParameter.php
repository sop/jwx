<?php

namespace JWX\JOSE\Parameter;

use JWX\JOSE\AlgorithmParameterValue;


class EncryptionAlgorithmParameter extends RegisteredParameter
{
	public function __construct($value) {
		parent::__construct(self::NAME_ENCRYPTION_ALGORITHM, $value);
	}
	
	public static function fromAlgorithm(AlgorithmParameterValue $value) {
		return new self($value->algorithmParamValue());
	}
}
