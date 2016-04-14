<?php

use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\EncryptionAlgorithm\A192CBCHS384Algorithm;
use JWX\JWE\EncryptionAlgorithm\A256CBCHS512Algorithm;


/**
 * @group jwe
 */
class DirectCEKTest extends PHPUnit_Framework_TestCase
{
	const PAYLOAD = "PAYLOAD";
	
	const CEK_A128 = "123456789 123456789 123456789 12";
	const CEK_A192 = "123456789 123456789 123456789 123456789 12345678";
	const CEK_A256 = self::CEK_A128 . self::CEK_A128;
	
	/**
	 *
	 * @return JWE
	 */
	public function testEncryptA128() {
		$cek = self::CEK_A128;
		$jwe = JWE::encrypt(self::PAYLOAD, $cek, new DirectCEKAlgorithm($cek), 
			new A128CBCHS256Algorithm());
		$this->assertInstanceOf(JWE::class, $jwe);
		return $jwe;
	}
	
	/**
	 * @depends testEncryptA128
	 *
	 * @param JWE $jwe
	 * @return string
	 */
	public function testToCompact(JWE $jwe) {
		$data = $jwe->toCompact();
		$this->assertTrue(is_string($data));
		return $data;
	}
	
	/**
	 * @depends testToCompact
	 *
	 * @param string $data
	 */
	public function testFromCompact($data) {
		$jwe = JWE::fromCompact($data);
		$this->assertInstanceOf(JWE::class, $jwe);
		return $jwe;
	}
	
	/**
	 * @depends testFromCompact
	 *
	 * @param JWE $jwe
	 */
	public function testDecryptA128(JWE $jwe) {
		$payload = $jwe->decrypt(new DirectCEKAlgorithm(self::CEK_A128), 
			new A128CBCHS256Algorithm());
		$this->assertEquals(self::PAYLOAD, $payload);
	}
	
	/**
	 *
	 * @return JWE
	 */
	public function testEncryptA192() {
		$cek = self::CEK_A192;
		$jwe = JWE::encrypt(self::PAYLOAD, $cek, new DirectCEKAlgorithm($cek), 
			new A192CBCHS384Algorithm());
		$this->assertInstanceOf(JWE::class, $jwe);
		return $jwe;
	}
	
	/**
	 * @depends testEncryptA192
	 *
	 * @param JWE $jwe
	 */
	public function testDecryptA192(JWE $jwe) {
		$payload = $jwe->decrypt(new DirectCEKAlgorithm(self::CEK_A192), 
			new A192CBCHS384Algorithm());
		$this->assertEquals(self::PAYLOAD, $payload);
	}
	
	/**
	 *
	 * @return JWE
	 */
	public function testEncryptA256() {
		$cek = self::CEK_A256;
		$jwe = JWE::encrypt(self::PAYLOAD, $cek, new DirectCEKAlgorithm($cek), 
			new A256CBCHS512Algorithm());
		$this->assertInstanceOf(JWE::class, $jwe);
		return $jwe;
	}
	
	/**
	 * @depends testEncryptA256
	 *
	 * @param JWE $jwe
	 */
	public function testDecryptA256(JWE $jwe) {
		$payload = $jwe->decrypt(new DirectCEKAlgorithm(self::CEK_A256), 
			new A256CBCHS512Algorithm());
		$this->assertEquals(self::PAYLOAD, $payload);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testInvalidKeySize() {
		$cek = "nope";
		JWE::encrypt(self::PAYLOAD, $cek, new DirectCEKAlgorithm($cek), 
			new A128CBCHS256Algorithm());
	}
}