<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWT\Parameter\AlgorithmParameter;


/**
 * Key Encryption with RSAES OAEP
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.3
 */
class RSAOAEPAlgorithm extends RSAESKeyAlgorithm
{
	protected function _paddingScheme() {
		return OPENSSL_PKCS1_OAEP_PADDING;
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_RSA_OAEP;
	}
}
