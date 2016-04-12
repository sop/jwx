<?php

namespace JWX\JWT\Parameter;


class EncryptionAlgorithmParameter extends RegisteredJWTParameter
{
	public function __construct($value) {
		parent::__construct(self::PARAM_ENCRYPTION_ALGORITHM, $value);
	}
	
	public static function fromAlgorithm(
			EncryptionAlgorithmParameterValue $value) {
		return new self($value->encryptionAlgorithmParamValue());
	}
}
