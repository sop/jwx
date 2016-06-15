<?php

use JWX\JWE\EncryptionAlgorithm\EncryptionAlgorithmFactory;
use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\RSAESPKCS1Algorithm;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\JWT\Header\Header;
use JWX\Util\Base64;


class CookbookKeyEncRSA15AndAESHMACSHA2Test extends PHPUnit_Framework_TestCase
{
	private static $_testData;
	
	public static function setUpBeforeClass() {
		$json = file_get_contents(
			COOKBOOK_DIR .
				 "/jwe/5_1.key_encryption_using_rsa_v15_and_aes-hmac-sha2.json");
		self::$_testData = json_decode($json, true);
	}
	
	public static function tearDownAfterClass() {
		self::$_testData = null;
	}
	
	public function testPrivateKey() {
		$jwk = RSAPrivateKeyJWK::fromArray(self::$_testData["input"]["key"]);
		$this->assertInstanceOf(RSAPrivateKeyJWK::class, $jwk);
		return $jwk;
	}
	
	/**
	 * @depends testPrivateKey
	 *
	 * Encryption result cannot be verified since RSAES uses random salt.
	 *
	 * @param RSAPrivateKeyJWK $jwk
	 */
	public function testEncryptedKey(RSAPrivateKeyJWK $jwk) {
		$cek = Base64::urlDecode(self::$_testData["generated"]["cek"]);
		$algo = RSAESPKCS1Algorithm::fromPrivateKey($jwk);
		$ciphertext = $algo->encrypt($cek);
		// test that decrypt succeeds
		$result = $algo->decrypt($ciphertext);
		$this->assertEquals($cek, $result);
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
	 * @depends testPrivateKey
	 * @depends testHeader
	 */
	public function testCreateJWE(RSAPrivateKeyJWK $jwk, Header $header) {
		$payload = self::$_testData["input"]["plaintext"];
		$cek = Base64::urlDecode(self::$_testData["generated"]["cek"]);
		$iv = Base64::urlDecode(self::$_testData["generated"]["iv"]);
		$key_algo = RSAESPKCS1Algorithm::fromPrivateKey($jwk);
		$enc_algo = EncryptionAlgorithmFactory::algoByName(
			self::$_testData["input"]["enc"]);
		$jwe = JWE::encrypt($payload, $key_algo, $enc_algo, null, $header, $cek, 
			$iv);
		$this->assertInstanceOf(JWE::class, $jwe);
		return $jwe;
	}
}
