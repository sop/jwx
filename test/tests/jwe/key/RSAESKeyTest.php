<?php

use CryptoUtil\PEM\PEM;
use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\RSAESKeyAlgorithm;
use JWX\JWE\KeyAlgorithm\RSAESPKCS1Algorithm;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWK\RSA\RSAPrivateKeyJWK;


/**
 * @group jwe
 * @group key
 */
class RSAESKeyTest extends PHPUnit_Framework_TestCase
{
	private static $_publicKey;
	
	private static $_privateKey;
	
	public static function setUpBeforeClass() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem");
		self::$_privateKey = RSAPrivateKeyJWK::fromPEM($pem);
		self::$_publicKey = self::$_privateKey->publicKey();
	}
	
	public static function tearDownAfterClass() {
		self::$_publicKey = null;
		self::$_privateKey = null;
	}
	
	public function testCreate() {
		$algo = RSAESPKCS1Algorithm::fromPrivateKey(self::$_privateKey);
		$this->assertInstanceOf(RSAESKeyAlgorithm::class, $algo);
		return $algo;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param KeyManagementAlgorithm $algo
	 */
	public function testHeaderParameters(KeyManagementAlgorithm $algo) {
		$params = $algo->headerParameters();
		$this->assertCount(1, $params);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param RSAESKeyAlgorithm $algo
	 */
	public function testPublicKey(RSAESKeyAlgorithm $algo) {
		$this->assertEquals(self::$_publicKey, $algo->publicKey());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param RSAESKeyAlgorithm $algo
	 */
	public function testHasPrivateKey(RSAESKeyAlgorithm $algo) {
		$this->assertTrue($algo->hasPrivateKey());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param RSAESKeyAlgorithm $algo
	 */
	public function testPrivateKey(RSAESKeyAlgorithm $algo) {
		$this->assertEquals(self::$_privateKey, $algo->privateKey());
	}
}
