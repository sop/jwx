<?php

use JWX\JWE\ContentEncryptionAlgorithm;
use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\EncryptionAlgorithm\AESCBCAlgorithm;


/**
 * @group jwe
 * @group encryption
 */
class AESCBCEncryptionTest extends PHPUnit_Framework_TestCase
{
	const KEY_128 = "123456789 123456789 123456789 12";
	const IV = "123456789 123456";
	
	public function testCreate() {
		$algo = new A128CBCHS256Algorithm();
		$this->assertInstanceOf(AESCBCAlgorithm::class, $algo);
		return $algo;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param ContentEncryptionAlgorithm $algo
	 */
	public function testIVSize(ContentEncryptionAlgorithm $algo) {
		$this->assertEquals(16, $algo->ivSize());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AESCBCAlgorithm $algo
	 */
	public function testRandomCEK(AESCBCAlgorithm $algo) {
		$cek = $algo->generateRandomCEK();
		$this->assertEquals(32, strlen($cek));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param ContentEncryptionAlgorithm $algo
	 */
	public function testHeaderParams(ContentEncryptionAlgorithm $algo) {
		$params = $algo->headerParameters();
		$this->assertCount(1, $params);
	}
	
	/**
	 * @depends testCreate
	 * @expectedException RuntimeException
	 *
	 * @param ContentEncryptionAlgorithm $algo
	 */
	public function testInvalidKeySize(ContentEncryptionAlgorithm $algo) {
		$algo->encrypt("test", "1234", self::IV, "");
	}
	
	/**
	 * @depends testCreate
	 * @expectedException RuntimeException
	 *
	 * @param ContentEncryptionAlgorithm $algo
	 */
	public function testInvalidIVSize(ContentEncryptionAlgorithm $algo) {
		$algo->encrypt("test", self::KEY_128, "1234", "");
	}
	
	/**
	 * @depends testCreate
	 * @expectedException JWX\JWE\Exception\AuthenticationException
	 *
	 * @param ContentEncryptionAlgorithm $algo
	 */
	public function testAuthFail(ContentEncryptionAlgorithm $algo) {
		static $data = "test";
		list($ciphertext, $auth_tag) = $algo->encrypt($data, self::KEY_128, 
			self::IV, "");
		$algo->decrypt($ciphertext, self::KEY_128, self::IV, "", 
			strrev($auth_tag));
	}
}
