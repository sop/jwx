<?php

use JWX\JWE\CompressionAlgorithm\DeflateAlgorithm;
use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use JWX\JWT\JWT;


/**
 * @group jwe
 */
class DeflateTest extends PHPUnit_Framework_TestCase
{
	const PAYLOAD = "My hovercraft is full of eels.";
	const CEK_A128 = "123456789 123456789 123456789 12";
	
	public function testCompress() {
		$compressor = new DeflateAlgorithm();
		$data = $compressor->compress(self::PAYLOAD);
		$this->assertTrue(is_string($data));
		return $data;
	}
	
	/**
	 * @depends testCompress
	 *
	 * @param string $data
	 */
	public function testDecompress($data) {
		$decompressor = new DeflateAlgorithm();
		$payload = $decompressor->decompress($data);
		$this->assertEquals(self::PAYLOAD, $payload);
	}
	
	public function testEncode() {
		$jwe = JWE::encrypt(self::PAYLOAD, self::CEK_A128, 
			new DirectCEKAlgorithm(self::CEK_A128), new A128CBCHS256Algorithm(), 
			new DeflateAlgorithm());
		$this->assertInstanceOf(JWE::class, $jwe);
		return $jwe->toCompact();
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $token
	 */
	public function testDecode($token) {
		$jwt = new JWT($token);
		$payload = $jwt->JWE()->decrypt(new DirectCEKAlgorithm(self::CEK_A128), 
			new A128CBCHS256Algorithm());
		$this->assertEquals(self::PAYLOAD, $payload);
	}
}