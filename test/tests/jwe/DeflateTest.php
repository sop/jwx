<?php

use JWX\JWT\JWT;
use JWX\JWT\Header;
use JWX\JWT\Parameter\CompressionAlgorithmParameter;
use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\CompressionAlgorithm\DeflateAlgorithm;


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
		$header = new Header(
			new CompressionAlgorithmParameter(
				CompressionAlgorithmParameter::ALGO_DEFLATE));
		$jwe = JWE::encrypt(self::PAYLOAD, self::CEK_A128, 
			new DirectCEKAlgorithm(self::CEK_A128), new A128CBCHS256Algorithm(), 
			$header);
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