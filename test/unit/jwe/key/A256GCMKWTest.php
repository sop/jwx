<?php

use JWX\JWA\JWA;
use JWX\JWE\KeyAlgorithm\A256GCMKWAlgorithm;
use JWX\JWE\KeyAlgorithm\AESGCMKWAlgorithm;


/**
 * @group jwe
 * @group key
 */
class A256GCMKWTest extends PHPUnit_Framework_TestCase
{
	const KEY_256 = "123456789 123456789 123456789 12";
	const IV = "123456789 12";
	const CEK_128 = "987654321 987654";
	
	public function testCreate() {
		$algo = new A256GCMKWAlgorithm(self::KEY_256, self::IV);
		$this->assertInstanceOf(AESGCMKWAlgorithm::class, $algo);
		return $algo;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AESGCMKWAlgorithm $algo
	 */
	public function testAlgoParamValue(AESGCMKWAlgorithm $algo) {
		$this->assertEquals(JWA::ALGO_A256GCMKW, $algo->algorithmParamValue());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AESGCMKWAlgorithm $algo
	 */
	public function testEncrypt(AESGCMKWAlgorithm $algo) {
		$ciphertext = $algo->encrypt(self::CEK_128, $header);
		$this->assertNotEquals(self::CEK_128, $ciphertext);
		return [$ciphertext, $header];
	}
	
	/**
	 * @depends testCreate
	 * @depends testEncrypt
	 *
	 * @param AESGCMKWAlgorithm $algo
	 * @param array $data
	 */
	public function testDecrypt(AESGCMKWAlgorithm $algo, $data) {
		list($ciphertext, $header) = $data;
		$cek = $algo->decrypt($ciphertext, $header);
		$this->assertEquals(self::CEK_128, $cek);
	}
	
	/**
	 * @expectedException LengthException
	 */
	public function testInvalidKeySize() {
		$algo = new A256GCMKWAlgorithm("fail", self::IV);
		$algo->encrypt(self::CEK_128);
	}
}
