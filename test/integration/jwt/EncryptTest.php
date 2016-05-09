<?php

use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\KeyAlgorithm\PBES2HS256A128KWAlgorithm;
use JWX\JWT\Claim\IssuedAtClaim;
use JWX\JWT\Claims;
use JWX\JWT\JWT;
use JWX\JWT\ValidationContext;


/**
 * @group jwt
 * @group jwe
 */
class JWTEncryptTest extends PHPUnit_Framework_TestCase
{
	private static $_claims;
	
	private static $_keyAlgo;
	
	private static $_encAlgo;
	
	public static function setUpBeforeClass() {
		self::$_claims = new Claims(IssuedAtClaim::now());
		self::$_keyAlgo = PBES2HS256A128KWAlgorithm::fromPassword("p4s5W0rD");
		self::$_encAlgo = new A128CBCHS256Algorithm();
	}
	
	public static function tearDownAfterClass() {
		self::$_claims = null;
		self::$_keyAlgo = null;
		self::$_encAlgo = null;
	}
	
	public function testCreate() {
		$jwt = JWT::encryptedFromClaims(self::$_claims, self::$_keyAlgo, 
			self::$_encAlgo);
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
		$claims = $jwt->claimsFromJWE(self::$_keyAlgo, self::$_encAlgo, $ctx);
		$this->assertEquals(self::$_claims, $claims);
	}
}
