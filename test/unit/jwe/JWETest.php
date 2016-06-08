<?php

use JWX\JWE\CompressionAlgorithm\DeflateAlgorithm;
use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWT\Header\Header;
use JWX\JWT\Header\JOSE;
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
		$jwe = JWE::encrypt(self::PAYLOAD, self::$_keyAlgo, self::$_encAlgo);
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
		$this->assertInternalType("string", $jwe->initializationVector());
	}
	
	/**
	 * @depends testEncrypt
	 *
	 * @param JWE $jwe
	 */
	public function testCiphertext(JWE $jwe) {
		$this->assertInternalType("string", $jwe->ciphertext());
	}
	
	/**
	 * @depends testEncrypt
	 *
	 * @param JWE $jwe
	 */
	public function testAuthTag(JWE $jwe) {
		$this->assertInternalType("string", $jwe->authenticationTag());
	}
	
	/**
	 * @depends testEncrypt
	 *
	 * @param JWE $jwe
	 */
	public function testToCompact(JWE $jwe) {
		$data = $jwe->toCompact();
		$this->assertInternalType("string", $data);
		return $data;
	}
	
	/**
	 * @depends testEncrypt
	 *
	 * @param JWE $jwe
	 */
	public function testToString(JWE $jwe) {
		$token = strval($jwe);
		$this->assertInternalType("string", $token);
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
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromPartsFail() {
		JWE::fromParts(array());
	}
	
	public function testEncryptWithAll() {
		$zip_algo = new DeflateAlgorithm();
		$header = new Header(new JWTParameter("test", "value"));
		static $iv = "0123456789abcdef";
		$jwe = JWE::encrypt(self::PAYLOAD, self::$_keyAlgo, self::$_encAlgo, 
			$zip_algo, $header, self::CEK, $iv);
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
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testEncryptInvalidKeySize() {
		JWE::encrypt(self::PAYLOAD, self::$_keyAlgo, self::$_encAlgo, null, 
			null, "nope");
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testEncryptInvalidIVSize() {
		JWE::encrypt(self::PAYLOAD, self::$_keyAlgo, self::$_encAlgo, null, 
			null, null, "nope");
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testKeyEncryptUnsetsHeader() {
		$key_algo = new JWETest_EvilKeyAlgo();
		JWE::encrypt(self::PAYLOAD, $key_algo, self::$_encAlgo);
	}
}


class JWETest_EvilKeyAlgo extends KeyManagementAlgorithm
{
	protected function _encryptKey($key, Header &$header) {
		$header = null;
		return $key;
	}
	
	protected function _decryptKey($ciphertext, Header $header) {
		return $ciphertext;
	}
	
	public function cekForEncryption($length) {
		return str_repeat("\0", $length);
	}
	
	public function algorithmParamValue() {
		return "test";
	}
	
	public function headerParameters() {
		return array();
	}
}
