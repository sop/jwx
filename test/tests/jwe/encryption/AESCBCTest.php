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
}
