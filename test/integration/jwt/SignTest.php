<?php

use JWX\JWS\Algorithm\HS256Algorithm;
use JWX\JWT\Claim\IssuedAtClaim;
use JWX\JWT\Claims;
use JWX\JWT\JWT;
use JWX\JWT\ValidationContext;


/**
 * @group jwt
 * @group jws
 */
class JWTSigningTest extends PHPUnit_Framework_TestCase
{
	private static $_claims;
	
	private static $_signatureAlgo;
	
	public static function setUpBeforeClass() {
		self::$_claims = new Claims(IssuedAtClaim::now());
		self::$_signatureAlgo = new HS256Algorithm("secret");
	}
	
	public static function tearDownAfterClass() {
		self::$_claims = null;
		self::$_signatureAlgo = null;
	}
	
	public function testCreate() {
		$jwt = JWT::signedFromClaims(self::$_claims, self::$_signatureAlgo);
		$this->assertInstanceOf(JWT::class, $jwt);
		return $jwt;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWT $jwt
	 */
	public function testDecrypt(JWT $jwt) {
		$ctx = new ValidationContext();
		$claims = $jwt->claimsFromJWS(self::$_signatureAlgo, $ctx);
		$this->assertEquals(self::$_claims, $claims);
	}
}
