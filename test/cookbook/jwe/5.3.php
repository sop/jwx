<?php

use JWX\JWE\EncryptionAlgorithm\EncryptionAlgorithmFactory;
use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\PBES2Algorithm;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWT\Header\Header;
use JWX\Util\Base64;


class CookbookKeyWrapPBES2AndAESHMACSHA2Test extends PHPUnit_Framework_TestCase
{
	private static $_testData;
	
	public static function setUpBeforeClass() {
		$json = file_get_contents(
			COOKBOOK_DIR .
				 "/jwe/5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2.json");
		self::$_testData = json_decode($json, true);
	}
	
	public static function tearDownAfterClass() {
		self::$_testData = null;
	}
	
	public function testHeader() {
		$header = Header::fromArray(
			self::$_testData["encrypting_content"]["protected"]);
		$encoded = Base64::urlEncode($header->toJSON());
		$this->assertEquals(
			self::$_testData["encrypting_content"]["protected_b64u"], $encoded);
		return $header;
	}
	
	/**
	 * @depends testHeader
	 *
	 * @param Header $header
	 */
	public function testEncryptedKey(Header $header) {
		$cek = Base64::urlDecode(self::$_testData["generated"]["cek"]);
		$password = self::$_testData["input"]["pwd"];
		$algo = PBES2Algorithm::fromJWK(SymmetricKeyJWK::fromKey($password), 
			$header);
		$ciphertext = $algo->encrypt($cek);
		$this->assertEquals(self::$_testData["encrypting_key"]["encrypted_key"], 
			Base64::urlEncode($ciphertext));
	}
	
	/**
	 * @depends testHeader
	 *
	 * @param Header $header
	 */
	public function testContentEncryption(Header $header) {
		$plaintext = self::$_testData["input"]["plaintext"];
		$cek = Base64::urlDecode(self::$_testData["generated"]["cek"]);
		$iv = Base64::urlDecode(self::$_testData["generated"]["iv"]);
		$aad = Base64::urlEncode($header->toJSON());
		$algo = EncryptionAlgorithmFactory::algoByName(
			self::$_testData["input"]["enc"]);
		list($ciphertext, $auth_tag) = $algo->encrypt($plaintext, $cek, $iv, 
			$aad);
		$this->assertEquals(
			self::$_testData["encrypting_content"]["ciphertext"], 
			Base64::urlEncode($ciphertext));
		$this->assertEquals(self::$_testData["encrypting_content"]["tag"], 
			Base64::urlEncode($auth_tag));
	}
	
	/**
	 * @depends testHeader
	 */
	public function testCreateJWE(Header $header) {
		$payload = self::$_testData["input"]["plaintext"];
		$cek = Base64::urlDecode(self::$_testData["generated"]["cek"]);
		$iv = Base64::urlDecode(self::$_testData["generated"]["iv"]);
		$password = self::$_testData["input"]["pwd"];
		$key_algo = PBES2Algorithm::fromJWK(SymmetricKeyJWK::fromKey($password), 
			$header);
		$enc_algo = EncryptionAlgorithmFactory::algoByName(
			self::$_testData["input"]["enc"]);
		$jwe = JWE::encrypt($payload, $key_algo, $enc_algo, null, $header, $cek, 
			$iv);
		$this->assertInstanceOf(JWE::class, $jwe);
		return $jwe;
	}
	
	/**
	 * @depends testCreateJWE
	 *
	 * @param JWE $jwe
	 */
	public function testCompact(JWE $jwe) {
		$this->assertEquals(self::$_testData["output"]["compact"], 
			$jwe->toCompact());
	}
}
