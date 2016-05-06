<?php

use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use JWX\JWS\Algorithm\NoneAlgorithm;
use JWX\JWS\JWS;
use JWX\JWT\Claim\SubjectClaim;
use JWX\JWT\Claims;
use JWX\JWT\JOSE;
use JWX\JWT\JWT;
use JWX\JWT\ValidationContext;


/**
 * @group jwt
 */
class JWTTest extends PHPUnit_Framework_TestCase
{
	private static $_claims;
	
	const KEY_128 = "123456789 123456789 123456789 12";
	
	public static function setUpBeforeClass() {
		self::$_claims = new Claims(new SubjectClaim("test"));
	}
	
	public static function tearDownAfterClass() {
		self::$_claims = null;
	}
	
	public function testCreateJWS() {
		$jwt = JWT::signedFromClaims(self::$_claims, new NoneAlgorithm());
		$this->assertInstanceOf(JWT::class, $jwt);
		return $jwt;
	}
	
	/**
	 * @depends testCreateJWS
	 *
	 * @param JWT $jwt
	 */
	public function testIsJWS(JWT $jwt) {
		$this->assertTrue($jwt->isJWS());
	}
	
	/**
	 * @depends testCreateJWS
	 *
	 * @param JWT $jwt
	 */
	public function testGetJWS(JWT $jwt) {
		$this->assertInstanceOf(JWS::class, $jwt->JWS());
	}
	
	/**
	 * @depends testCreateJWS
	 *
	 * @param JWT $jwt
	 */
	public function testHeader(JWT $jwt) {
		$header = $jwt->header();
		$this->assertInstanceOf(JOSE::class, $header);
	}
	
	/**
	 * @depends testCreateJWS
	 *
	 * @param JWT $jwt
	 */
	public function testToken(JWT $jwt) {
		$this->assertTrue(is_string($jwt->token()));
	}
	
	/**
	 * @depends testCreateJWS
	 *
	 * @param JWT $jwt
	 */
	public function testClaimsFromJWS(JWT $jwt) {
		$claims = $jwt->claimsFromJWS(new NoneAlgorithm(), 
			new ValidationContext());
		$this->assertEquals(self::$_claims, $claims);
	}
	
	public function testEncryptedFromClaims() {
		$key_algo = new DirectCEKAlgorithm(self::KEY_128);
		$enc_algo = new A128CBCHS256Algorithm();
		$jwt = JWT::encryptedFromClaims(self::$_claims, $key_algo, $enc_algo);
		$this->assertInstanceOf(JWT::class, $jwt);
	}
}
