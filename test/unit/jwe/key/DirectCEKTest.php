<?php

use JWX\JWA\JWA;
use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use JWX\JWE\KeyManagementAlgorithm;


/**
 * @group jwe
 * @group key
 */
class DirectCEKTest extends PHPUnit_Framework_TestCase
{
	const KEY_128 = "123456789 123456";
	
	public function testCreate() {
		$algo = new DirectCEKAlgorithm(self::KEY_128);
		$this->assertInstanceOf(DirectCEKAlgorithm::class, $algo);
		return $algo;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param DirectCEKAlgorithm $algo
	 */
	public function testCEK(DirectCEKAlgorithm $algo) {
		$this->assertEquals(self::KEY_128, $algo->cek());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param DirectCEKAlgorithm $algo
	 */
	public function testAlgoValue(DirectCEKAlgorithm $algo) {
		$this->assertEquals(JWA::ALGO_DIR, $algo->algorithmParamValue());
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
	 * @param DirectCEKAlgorithm $algo
	 */
	public function testEncrypt(DirectCEKAlgorithm $algo) {
		$data = $algo->encrypt(self::KEY_128);
		$this->assertEquals("", $data);
		return $data;
	}
	
	/**
	 * @depends testCreate
	 * @depends testEncrypt
	 *
	 * @param DirectCEKAlgorithm $algo
	 */
	public function testDecrypt(DirectCEKAlgorithm $algo, $data) {
		$cek = $algo->decrypt($data);
		$this->assertEquals(self::KEY_128, $cek);
	}
	
	/**
	 * @depends testCreate
	 * @expectedException UnexpectedValueException
	 *
	 * @param DirectCEKAlgorithm $algo
	 */
	public function testDecryptFail(DirectCEKAlgorithm $algo) {
		$algo->decrypt("x");
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param DirectCEKAlgorithm $algo
	 */
	public function testCEKForEncryption(DirectCEKAlgorithm $algo) {
		$cek = $algo->cekForEncryption(strlen(self::KEY_128));
		$this->assertEquals(self::KEY_128, $cek);
	}
	
	/**
	 * @depends testCreate
	 * @expectedException UnexpectedValueException
	 *
	 * @param DirectCEKAlgorithm $algo
	 */
	public function testCEKForEncryptionFail(DirectCEKAlgorithm $algo) {
		$algo->cekForEncryption(1);
	}
}
