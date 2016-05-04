<?php

use JWX\JWA\JWA;
use JWX\JWE\CompressionAlgorithm\DeflateAlgorithm;
use JWX\JWE\CompressionAlgorithm;
use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use JWX\JWT\JWT;


/**
 * @group jwe
 * @group compression
 */
class DeflateTest extends PHPUnit_Framework_TestCase
{
	const PAYLOAD = "My hovercraft is full of eels.";
	const CEK_A128 = "123456789 123456789 123456789 12";
	
	public function testCreate() {
		$algo = new DeflateAlgorithm();
		$this->assertInstanceOf(CompressionAlgorithm::class, $algo);
		return $algo;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CompressionAlgorithm $algo
	 */
	public function testCompressionParamValue(CompressionAlgorithm $algo) {
		$this->assertEquals(JWA::ALGO_DEFLATE, $algo->compressionParamValue());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CompressionAlgorithm $algo
	 */
	public function testCompress(CompressionAlgorithm $algo) {
		$data = $algo->compress(self::PAYLOAD);
		$this->assertTrue(is_string($data));
		return $data;
	}
	
	/**
	 * @depends testCreate
	 * @depends testCompress
	 *
	 * @param CompressionAlgorithm $algo
	 * @param string $data
	 */
	public function testDecompress(CompressionAlgorithm $algo, $data) {
		$payload = $algo->decompress($data);
		$this->assertEquals(self::PAYLOAD, $payload);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param CompressionAlgorithm $algo
	 */
	public function testEncrypt(CompressionAlgorithm $algo) {
		$key_algo = new DirectCEKAlgorithm(self::CEK_A128);
		$jwe = JWE::encrypt(self::PAYLOAD, $key_algo->cek(), $key_algo, 
			new A128CBCHS256Algorithm(), $algo);
		$this->assertInstanceOf(JWE::class, $jwe);
		return $jwe->toCompact();
	}
	
	/**
	 * @depends testEncrypt
	 *
	 * @param string $token
	 */
	public function testDecrypt($token) {
		$jwt = new JWT($token);
		$key_algo = new DirectCEKAlgorithm(self::CEK_A128);
		$payload = $jwt->JWE()->decrypt($key_algo, new A128CBCHS256Algorithm());
		$this->assertEquals(self::PAYLOAD, $payload);
	}
}
