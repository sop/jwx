<?php

use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use JWX\JWS\Algorithm\HS256Algorithm;
use JWX\JWS\Algorithm\NoneAlgorithm;
use JWX\JWS\JWS;
use JWX\JWT\Claim\SubjectClaim;
use JWX\JWT\Claims;
use JWX\JWT\JOSE;
use JWX\JWT\JWT;
use JWX\JWT\ValidationContext;
use JWX\Util\Base64;


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
	 * @expectedException LogicException
	 *
	 * @param JWT $jwt
	 */
	public function testGetJWEFail(JWT $jwt) {
		$jwt->JWE();
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
	public function testToString(JWT $jwt) {
		$token = strval($jwt);
		$this->assertTrue(is_string($token));
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
	
	/**
	 * @expectedException JWX\JWT\Exception\ValidationException
	 */
	public function testClaimsFromJWSFail() {
		$jwt = JWT::signedFromClaims(self::$_claims, new HS256Algorithm("key"));
		$parts = explode(".", $jwt->token());
		$parts[2] = Base64::urlEncode("\0");
		$jwt = new JWT(implode(".", $parts));
		$jwt->claimsFromJWS(new HS256Algorithm("yek"), new ValidationContext());
	}
	
	public function testEncryptedFromClaims() {
		$key_algo = new DirectCEKAlgorithm(self::KEY_128);
		$enc_algo = new A128CBCHS256Algorithm();
		$jwt = JWT::encryptedFromClaims(self::$_claims, $key_algo, $enc_algo);
		$this->assertInstanceOf(JWT::class, $jwt);
		return $jwt;
	}
	
	/**
	 * @depends testEncryptedFromClaims
	 *
	 * @param JWT $jwt
	 */
	public function testIsJWE(JWT $jwt) {
		$this->assertTrue($jwt->isJWE());
	}
	
	/**
	 * @depends testEncryptedFromClaims
	 *
	 * @param JWT $jwt
	 */
	public function testGetJWE(JWT $jwt) {
		$this->assertInstanceOf(JWE::class, $jwt->JWE());
	}
	
	/**
	 * @depends testEncryptedFromClaims
	 * @expectedException LogicException
	 *
	 * @param JWT $jwt
	 */
	public function testGetJWSFail(JWT $jwt) {
		$jwt->JWS();
	}
	
	/**
	 * @depends testEncryptedFromClaims
	 *
	 * @param JWT $jwt
	 */
	public function testClaimsFromJWE(JWT $jwt) {
		$key_algo = new DirectCEKAlgorithm(self::KEY_128);
		$enc_algo = new A128CBCHS256Algorithm();
		$claims = $jwt->claimsFromJWE($key_algo, $enc_algo, 
			new ValidationContext());
		$this->assertEquals(self::$_claims, $claims);
	}
	
	public function testUnsecuredFromClaims() {
		$jwt = JWT::unsecuredFromClaims(self::$_claims);
		$this->assertInstanceOf(JWT::class, $jwt);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidJWT() {
		new JWT("");
	}
}
