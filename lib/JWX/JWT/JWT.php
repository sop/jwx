<?php

namespace JWX\JWT;

use JWX\JWT\Claims;
use JWX\JWS\JWS;
use JWX\JWS\SignatureAlgorithm;
use JWX\JWS\Algorithm\NoneAlgorithm;


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
}
