<?php

use JWX\JWT\Header;
use JWX\JWS\JWS;
use JWX\JWS\Algorithm\RSASSAPKCS1Algorithm;
use JWX\JWK\JWK;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\Util\Base64;


class CookbookRSAv15SignatureTest extends PHPUnit_Framework_TestCase
{
	private static $_testData;
	
	public static function setUpBeforeClass() {
		$json = file_get_contents(
			COOKBOOK_DIR . "/jws/4_1.rsa_v15_signature.json");
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
	public function testSign(RSAPrivateKeyJWK $jwk, Header $header) {
		$payload = self::$_testData["input"]["payload"];
		$algo = RSASSAPKCS1Algorithm::fromJWK($jwk, 
			self::$_testData["input"]["alg"]);
		$jws = JWS::sign($payload, $algo, $header);
		$this->assertEquals(self::$_testData["signing"]["sig"], 
			Base64::urlEncode($jws->signature()));
		return $jws;
	}
	
	/**
	 * @depends testSign
	 *
	 * @param JWS $jws
	 */
	public function testCompact(JWS $jws) {
		$this->assertEquals(self::$_testData["output"]["compact"], 
			$jws->toCompact());
	}
}
