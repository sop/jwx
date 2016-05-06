<?php

use JWX\JWE\CompressionAlgorithm\DeflateAlgorithm;
use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use JWX\JWT\Header;
use JWX\JWT\JOSE;
use JWX\JWT\Parameter\JWTParameter;


/**
 * @group jwe
 */
class JWETest extends PHPUnit_Framework_TestCase
{
	const PAYLOAD = "PAYLOAD";
	const CEK = "123456789 123456789 123456789 12";
	
	private static $_keyAlgo;
	
	private static $_encAlgo;
	
	public static function setUpBeforeClass() {
		self::$_keyAlgo = new DirectCEKAlgorithm(self::CEK);
		self::$_encAlgo = new A128CBCHS256Algorithm();
	}
	
	public static function tearDownAfterClass() {
		self::$_keyAlgo = null;
		self::$_encAlgo = null;
	}
	
	public function testEncrypt() {
		$jwe = JWE::encrypt(self::PAYLOAD, self::$_keyAlgo->cek(), 
			self::$_keyAlgo, self::$_encAlgo);
		$this->assertInstanceOf(JWE::class, $jwe);
		return $jwe;
	}
	
	/**
	 * @depends testEncrypt
	 *
	 * @param JWE $jwe
	 */
	public function testDecrypt(JWE $jwe) {
		$payload = $jwe->decrypt(self::$_keyAlgo, self::$_encAlgo);
		$this->assertEquals(self::PAYLOAD, $payload);
	}
	
	/**
	 * @depends testEncrypt
	 *
	 * @param JWE $jwe
	 */
	public function testHeader(JWE $jwe) {
		$header = $jwe->header();
		$this->assertInstanceOf(JOSE::class, $header);
	}
	
	/**
	 * @depends testEncrypt
	 *
	 * @param JWE $jwe
	 */
	public function testEncryptedKey(JWE $jwe) {
		$this->assertEquals("", $jwe->encryptedKey());
	}
	
	/**
	 * @depends testEncrypt
	 *
	 * @param JWE $jwe
	 */
	public function testIV(JWE $jwe) {
		$this->assertTrue(is_string($jwe->initializationVector()));
	}
	
	/**
	 * @depends testEncrypt
	 *
	 * @param JWE $jwe
	 */
	public function testCiphertext(JWE $jwe) {
		$this->assertTrue(is_string($jwe->ciphertext()));
	}
	
	/**
	 * @depends testEncrypt
	 *
	 * @param JWE $jwe
	 */
	public function testAuthTag(JWE $jwe) {
		$this->assertTrue(is_string($jwe->authenticationTag()));
	}
	
	/**
	 * @depends testEncrypt
	 *
	 * @param JWE $jwe
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
	}
	
	public function testEncryptWithAll() {
		$zip_algo = new DeflateAlgorithm();
		$header = new Header(new JWTParameter("test", "value"));
		static $iv = "0123456789abcdef";
		$jwe = JWE::encrypt(self::PAYLOAD, self::$_keyAlgo->cek(), 
			self::$_keyAlgo, self::$_encAlgo, $zip_algo, $header, $iv);
		$this->assertInstanceOf(JWE::class, $jwe);
		return $jwe;
	}
	
	/**
	 * @depends testEncryptWithAll
	 *
	 * @param JWE $jwe
	 */
	public function testDecryptWithAll(JWE $jwe) {
		$payload = $jwe->decrypt(self::$_keyAlgo, self::$_encAlgo);
		$this->assertEquals(self::PAYLOAD, $payload);
	}
	
	/**
	 * @depends testEncryptWithAll
	 *
	 * @param JWE $jwe
	 */
	public function testCustomParameter(JWE $jwe) {
		$this->assertEquals("value", 
			$jwe->header()
				->get("test")
				->value());
	}
}
