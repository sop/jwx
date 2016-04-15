<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWT\Parameter\AlgorithmParameter;


/**
 * Key Encryption with RSAES-PKCS1-v1_5
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.2
 */
class RSAESPKCS1Algorithm extends RSAESKeyAlgorithm
{
	protected function _paddingScheme() {
		return OPENSSL_PKCS1_PADDING;
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_RSA1_5;
	}
}
