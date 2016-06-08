<?php

use JWX\JWE\CompressionAlgorithm\CompressionFactory;
use JWX\JWE\EncryptionAlgorithm\EncryptionFactory;
use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\AESKWAlgorithm;
use JWX\JWK\JWK;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWT\Header\Header;
use JWX\Util\Base64;


class CookbookCompressedContentTest extends PHPUnit_Framework_TestCase
{
	private static $_testData;
	
	public static function setUpBeforeClass() {
		$json = file_get_contents(
			COOKBOOK_DIR . "/jwe/5_9.compressed_content.json");
		self::$_testData = json_decode($json, true);
	}
	
	public static function tearDownAfterClass() {
		self::$_testData = null;
	}
	
	public function testCreateJWK() {
		$jwk = SymmetricKeyJWK::fromArray(self::$_testData["input"]["key"]);
		$this->assertInstanceOf(SymmetricKeyJWK::class, $jwk);
		return $jwk;
	}
	
	/**
	 * @depends testCreateJWK
	 *
	 * @param SymmetricKeyJWK $jwk
	 */
	public function testEncryptKey(SymmetricKeyJWK $jwk) {
		$algo = AESKWAlgorithm::fromJWK($jwk);
		$cek = Base64::urlDecode(self::$_testData["generated"]["cek"]);
		$enc_key = $algo->encrypt($cek);
		$this->assertEquals(self::$_testData["encrypting_key"]["encrypted_key"], 
			Base64::urlEncode($enc_key));
	}
	
	public function testCompressedContent() {
		$algo = CompressionFactory::algoByName(self::$_testData["input"]["zip"]);
		$content = $algo->compress(self::$_testData["input"]["plaintext"]);
		$this->assertEquals(self::$_testData["generated"]["plaintext_c"], 
			Base64::urlEncode($content));
		return $content;
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
	 * @depends testCreateJWK
	 * @depends testCompressedContent
	 * @depends testHeader
	 */
	public function testContentEncryption(SymmetricKeyJWK $jwk, $content, 
			Header $header) {
		$iv = Base64::urlDecode(self::$_testData["generated"]["iv"]);
		$aad = Base64::urlEncode($header->toJSON());
		$cek = AESKWAlgorithm::fromJWK($jwk)->decrypt(
			Base64::urlDecode(
				self::$_testData["encrypting_key"]["encrypted_key"]));
		$algo = EncryptionFactory::algoByName(self::$_testData["input"]["enc"]);
		list($ciphertext, $auth_tag) = $algo->encrypt($content, $cek, $iv, $aad);
		$this->assertEquals(
			self::$_testData["encrypting_content"]["ciphertext"], 
			Base64::urlEncode($ciphertext));
		$this->assertEquals(self::$_testData["encrypting_content"]["tag"], 
			Base64::urlEncode($auth_tag));
	}
	
	/**
	 * @depends testCreateJWK
	 * @depends testHeader
	 */
	public function testCreateJWE(SymmetricKeyJWK $jwk, Header $header) {
		$payload = self::$_testData["input"]["plaintext"];
		$cek = Base64::urlDecode(self::$_testData["generated"]["cek"]);
		$iv = Base64::urlDecode(self::$_testData["generated"]["iv"]);
		$key_algo = AESKWAlgorithm::fromJWK($jwk);
		$enc_algo = EncryptionFactory::algoByName(
			self::$_testData["input"]["enc"]);
		$zip_algo = CompressionFactory::algoByName(
			self::$_testData["input"]["zip"]);
		$jwe = JWE::encrypt($payload, $key_algo, $enc_algo, $zip_algo, $header, 
			$cek, $iv);
		$this->assertInstanceOf(JWE::class, $jwe);
		$this->assertEquals(self::$_testData["output"]["compact"], 
			$jwe->toCompact());
		return $jwe;
	}
}
