<?php

namespace JWX\JWT\Parameter;


/**
 * Implements 'Encryption Algorithm' parameter for JWE headers.
 *
 * @link https://tools.ietf.org/html/rfc7516#section-4.1.2
 */
class EncryptionAlgorithmParameter extends RegisteredJWTParameter
{
	/**
	 * Constructor
	 *
	 * @param string $algo Algorithm name
	 */
	public function __construct($algo) {
		parent::__construct(self::PARAM_ENCRYPTION_ALGORITHM, $algo);
	}
	
	/**
	 * Initialize from EncryptionAlgorithmParameterValue.
	 *
	 * @param EncryptionAlgorithmParameterValue $value
	 * @return self
	 */
	public static function fromAlgorithm(
			EncryptionAlgorithmParameterValue $value) {
		return new self($value->encryptionAlgorithmParamValue());
	}
}
