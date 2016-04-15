<?php

namespace JWX\JWT\Parameter;


/**
 * Encryption Algorithm parameter for JWE headers.
 *
 * @link https://tools.ietf.org/html/rfc7516#section-4.1.2
 * @link
 *       http://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
 */
class EncryptionAlgorithmParameter extends RegisteredJWTParameter
{
	const ALGO_A128CBC_HS256 = "A128CBC-HS256";
	const ALGO_A192CBC_HS384 = "A192CBC-HS384";
	const ALGO_A256CBC_HS512 = "A256CBC-HS512";
	const ALGO_A128GCM = "A128GCM";
	const ALGO_A192GCM = "A192GCM";
	const ALGO_A256GCM = "A256GCM";
	
	/**
	 * Constructor
	 *
	 * @param string $algo Algorithm name
	 */
	public function __construct($algo) {
		parent::__construct(self::PARAM_ENCRYPTION_ALGORITHM, $algo);
	}
	
	/**
	 * Initialize from EncryptionAlgorithmParameterValue
	 *
	 * @param EncryptionAlgorithmParameterValue $value
	 * @return self
	 */
	public static function fromAlgorithm(
		EncryptionAlgorithmParameterValue $value) {
		return new self($value->encryptionAlgorithmParamValue());
	}
}
