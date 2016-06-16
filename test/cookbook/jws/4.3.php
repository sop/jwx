<?php

use JWX\JWK\EC\ECPrivateKeyJWK;
use JWX\JWK\JWK;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\JWS\Algorithm\ECDSAAlgorithm;
use JWX\JWS\JWS;
use JWX\JWT\Header\Header;
use JWX\Util\Base64;


class CookbookECDSASignatureTest extends PHPUnit_Framework_TestCase
{
	private static $_testData;
	
	public static function setUpBeforeClass() {
		$json = file_get_contents(
			COOKBOOK_DIR . "/jws/4_3.ecdsa_signature.json");
		self::$_testData = json_decode($json, true);
	}
	
	public static function tearDownAfterClass() {
		self::$_testData = null;
	}
	
	public function testPrivateKey() {
		$jwk = ECPrivateKeyJWK::fromArray(self::$_testData["input"]["key"]);
		$this->assertInstanceOf(ECPrivateKeyJWK::class, $jwk);
		return $jwk;
	}
	
	public function testHeader() {
		$header = Header::fromArray(self::$_testData["signing"]["protected"]);
		$encoded = Base64::urlEncode($header->toJSON());
		$this->assertEquals(self::$_testData["signing"]["protected_b64u"], 
			$encoded);
		return $header;
	}
	
	/**
	 * @depends testPrivateKey
	 * @depends testHeader
	 *
	 * @param RSAPrivateKeyJWK $jwk
	 * @param Header $header
	 */
	public function testSign(ECPrivateKeyJWK $jwk, Header $header) {
		$payload = self::$_testData["input"]["payload"];
		$algo = ECDSAAlgorithm::fromJWK($jwk, $header);
		$jws = JWS::sign($payload, $algo, $header);
		$expected_sig = Base64::urlDecode(self::$_testData["signing"]["sig"]);
		// signature contains random data, so bytewise equality cannot be asserted
		$this->assertEquals(strlen($expected_sig), strlen($jws->signature()));
		return $jws;
	}
	
	/**
	 * @depends testSign
	 * @depends testPrivateKey
	 *
	 * @param JWS $jws
	 * @param ECPrivateKeyJWK $jwk
	 */
	public function testValidate(JWS $jws, ECPrivateKeyJWK $jwk) {
		$this->assertTrue($jws->validateWithJWK($jwk));
	}
}
