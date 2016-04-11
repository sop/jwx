<?php

namespace JWX\JWT;

use JWX\Header\JOSE;
use JWX\Header\Header;
use JWX\JWT\Claims;
use JWX\JWS\JWS;
use JWX\JWS\SignatureAlgorithm;
use JWX\JWS\Algorithm\NoneAlgorithm;
use JWX\JWE\JWE;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWE\ContentEncryptionAlgorithm;


class JWT
{
	/**
	 * Convert claims set to unsecured JWT token
	 *
	 * @param Claims $claims
	 * @return string
	 */
	public static function claimsToUnsecuredToken(Claims $claims) {
		return self::claimsToSignedToken($claims, new NoneAlgorithm());
	}
	
	/**
	 * Convert claims set to signed JWS token
	 *
	 * @param Claims $claims
	 * @param SignatureAlgorithm $algo
	 * @return string
	 */
	public static function claimsToSignedToken(Claims $claims, 
			SignatureAlgorithm $algo) {
		$payload = $claims->toJSON();
		return JWS::sign($payload, $algo)->toCompact();
	}
	
	/**
	 * Convert claims set to encrypted JWE token
	 * 
	 * @param Claims $claims
	 * @param KeyManagementAlgorithm $key_algo
	 * @param ContentEncryptionAlgorithm $enc_algo
	 * @return string
	 */
	public static function claimsToEncryptedToken(Claims $claims, 
			KeyManagementAlgorithm $key_algo, 
			ContentEncryptionAlgorithm $enc_algo) {
		$payload = $claims->toJSON();
		return JWE::encrypt($payload, $key_algo, $enc_algo)->toCompact();
	}
	
	/**
	 * Extract JOSE header from JWT token
	 *
	 * @param string $token
	 * @throws \UnexpectedValueException
	 * @return JOSE
	 */
	public static function headerFromToken($token) {
		$pos = strpos($token, ".");
		if (false === $pos) {
			throw new \UnexpectedValueException("Not a valid JWT");
		}
		$header = Header::fromJSON(substr($token, 0, $pos));
		return new JOSE($header);
	}
}
