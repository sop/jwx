<?php

use JWX\JWE\KeyAlgorithm\A128KWAlgorithm;
use JWX\JWE\KeyAlgorithm\AESKWAlgorithm;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWT\Parameter\JWTParameter;


/**
 * @group jwe
 * @group key
 */
class AESKWTest extends PHPUnit_Framework_TestCase
{
	const KEY_128 = "123456789 123456789 123456789 12";
	
	public function testCreate() {
		$algo = new A128KWAlgorithm(self::KEY_128);
		$this->assertInstanceOf(AESKWAlgorithm::class, $algo);
		return $algo;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param KeyManagementAlgorithm $algo
	 */
	public function testHeaderParameters(KeyManagementAlgorithm $algo) {
		$params = $algo->headerParameters();
		$this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param KeyManagementAlgorithm $algo
	 */
	public function testCEKForEncryption(KeyManagementAlgorithm $algo) {
		$cek = $algo->cekForEncryption(16);
		$this->assertEquals(16, strlen($cek));
	}
	
	/**
	 * @depends testCreate
	 * @expectedException RuntimeException
	 *
	 * @param KeyManagementAlgorithm $algo
	 */
	public function testCEKForEncryptionFail(KeyManagementAlgorithm $algo) {
		$algo->cekForEncryption(0);
	}
}
