<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWA\JWA;


/**
 * Implements key encryption with RSAES OAEP.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.3
 */
class RSAOAEPAlgorithm extends RSAESKeyAlgorithm
{
	protected function _paddingScheme() {
		return OPENSSL_PKCS1_OAEP_PADDING;
	}
	
	public function algorithmParamValue() {
		return JWA::ALGO_RSA_OAEP;
	}
}
