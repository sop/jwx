<?php

namespace JWX\JWT\Parameter;


/**
 * Algorithm parameter for JWS/JWE headers.
 *
 * @link https://tools.ietf.org/html/rfc7515#section-4.1.1
 * @link https://tools.ietf.org/html/rfc7516#section-4.1.1
 * @link
 *       http://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
 */
class AlgorithmParameter extends RegisteredJWTParameter
{
	const ALGO_HS256 = "HS256";
	const ALGO_HS384 = "HS384";
	const ALGO_HS512 = "HS512";
	const ALGO_RS256 = "RS256";
	const ALGO_RS384 = "RS384";
	const ALGO_RS512 = "RS512";
	const ALGO_ES256 = "ES256";
	const ALGO_ES384 = "ES384";
	const ALGO_ES512 = "ES512";
	const ALGO_PS256 = "PS256";
	const ALGO_PS384 = "PS384";
	const ALGO_PS512 = "PS512";
	const ALGO_NONE = "none";
	const ALGO_RSA1_5 = "RSA1_5";
	const ALGO_RSA_OAEP = "RSA-OAEP";
	const ALGO_RSA_OAEP256 = "RSA-OAEP-256";
	const ALGO_A128KW = "A128KW";
	const ALGO_A192KW = "A192KW";
	const ALGO_A256KW = "A256KW";
	const ALGO_DIR = "dir";
	const ALGO_ECDH_ES = "ECDH-ES";
	const ALGO_ECDH_ES_A128KW = "ECDH-ES+A128KW";
	const ALGO_ECDH_ES_A192KW = "ECDH-ES+A192KW";
	const ALGO_ECDH_ES_A256KW = "ECDH-ES+A256KW";
	const ALGO_A128GCMKW = "A128GCMKW";
	const ALGO_A192GCMKW = "A192GCMKW";
	const ALGO_A256GCMKW = "A256GCMKW";
	const ALGO_PBES2_HS256_A128KW = "PBES2-HS256+A128KW";
	const ALGO_PBES2_HS384_A192KW = "PBES2-HS384+A192KW";
	const ALGO_PBES2_HS512_A256KW = "PBES2-HS512+A256KW";
	
	/**
	 * Constructor
	 *
	 * @param string $algo Algorithm name
	 */
	public function __construct($algo) {
		parent::__construct(self::PARAM_ALGORITHM, (string) $algo);
	}
	
	/**
	 * Initialize from AlgorithmParameterValue
	 *
	 * @param AlgorithmParameterValue $value
	 * @return self
	 */
	public static function fromAlgorithm(AlgorithmParameterValue $value) {
		return new self($value->algorithmParamValue());
	}
}
