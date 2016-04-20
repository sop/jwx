<?php

use JWX\JWT\Header;
use JWX\JWS\JWS;
use JWX\JWS\Algorithm\HMACAlgorithm;
use JWX\JWK\JWK;
use JWX\JWK\SymmetricKeyJWK;
use JWX\Util\Base64;


class CookbookHMACSHA2IntegrityProtectionTest extends PHPUnit_Framework_TestCase
{
	private static $_testData;
	
	public static function setUpBeforeClass() {
		$json = file_get_contents(
			COOKBOOK_DIR . "/jws/4_4.hmac-sha2_integrity_protection.json");
		self::$_testData = json_decode($json, true);
	}
	
	public static function tearDownAfterClass() {
		self::$_testData = null;
	}
	
	public function testSymmetricKey() {
		$jwk = SymmetricKeyJWK::fromArray(self::$_testData["input"]["key"]);
		$this->assertInstanceOf(SymmetricKeyJWK::class, $jwk);
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
	 * @depends testSymmetricKey
	 * @depends testHeader
	 *
	 * @param SymmetricKeyJWK $jwk
	 * @param Header $header
	 */
	public function testSign(SymmetricKeyJWK $jwk, Header $header) {
		$payload = self::$_testData["input"]["payload"];
		$algo = HMACAlgorithm::fromJWK($jwk);
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
