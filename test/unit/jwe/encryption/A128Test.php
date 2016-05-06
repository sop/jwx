<?php

use JWX\JWA\JWA;
use JWX\JWE\ContentEncryptionAlgorithm;
use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\EncryptionAlgorithm\AESCBCAlgorithm;


/**
 * @group jwe
 * @group encryption
 */
class A128CBCEncryptionTest extends PHPUnit_Framework_TestCase
{
	const PLAINTEXT = "My hovercraft is full of eels.";
	const KEY_128 = "123456789 123456789 123456789 12";
	const IV = "123456789 123456";
	const AAD = "I will not buy this record, it is scratched.";
	
	public function testCreate() {
		$algo = new A128CBCHS256Algorithm();
		$this->assertInstanceOf(ContentEncryptionAlgorithm::class, $algo);
		return $algo;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param ContentEncryptionAlgorithm $algo
	 */
	public function testKeySize(AESCBCAlgorithm $algo) {
		$this->assertEquals(32, $algo->keySize());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param ContentEncryptionAlgorithm $algo
	 */
	public function testAlgoParamValue(ContentEncryptionAlgorithm $algo) {
		$this->assertEquals(JWA::ALGO_A128CBC_HS256, 
			$algo->encryptionAlgorithmParamValue());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param ContentEncryptionAlgorithm $algo
	 */
	public function testEncrypt(ContentEncryptionAlgorithm $algo) {
		list($ciphertext, $auth_tag) = $algo->encrypt(self::PLAINTEXT, 
			self::KEY_128, self::IV, self::AAD);
		$this->assertNotEquals(self::PLAINTEXT, $ciphertext);
		return [$ciphertext, $auth_tag];
	}
	
	/**
	 * @depends testCreate
	 * @depends testEncrypt
	 * 
	 * @param array $data
	 */
	public function testDecrypt(ContentEncryptionAlgorithm $algo, array $data) {
		$plaintext = $algo->decrypt($data[0], self::KEY_128, self::IV, 
			self::AAD, $data[1]);
		$this->assertEquals(self::PLAINTEXT, $plaintext);
	}
}
