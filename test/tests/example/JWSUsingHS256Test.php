<?php

use JWX\Util\Base64;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\RegisteredJWKParameter;
use JWX\JWS\Algorithm\HS256Algorithm;


/**
 * Test case for rfc7515 appendix A.1.
 * Example JWS Using HMAC SHA-256
 *
 * @group example
 *
 * @link https://tools.ietf.org/html/rfc7515#appendix-A.1
 */
class JWSUsingHS256Test extends PHPUnit_Framework_TestCase
{
	private static $_headerBytes = [123, 34, 116, 121, 112, 34, 58, 34, 74, 
		87, 84, 34, 44, 13, 10, 32, 34, 97, 108, 103, 34, 58, 34, 72, 83, 50, 53, 
		54, 34, 125];
	
	private static $_payloadBytes = [123, 34, 105, 115, 115, 34, 58, 34, 
		106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 
		48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 
		47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 
		95, 114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125];
	
	private static $_jwk = <<<EOF
{"kty":"oct",
 "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
}
EOF;
	
	public function testHeader() {
		static $expected = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
		$json = implode("", array_map("chr", self::$_headerBytes));
		$header = Base64::urlEncode($json);
		$this->assertEquals($expected, $header);
		return $header;
	}
	
	public function testPayload() {
		static $expected_data = <<<EOF
eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
EOF;
		$expected = str_replace(["\r", "\n"], "", $expected_data);
		$json = implode("", array_map("chr", self::$_payloadBytes));
		$payload = Base64::urlEncode($json);
		$this->assertEquals($expected, $payload);
		return $payload;
	}
	
	public function testKey() {
		$jwk = JWK::fromJSON(self::$_jwk);
		$key = $jwk->get(RegisteredJWKParameter::PARAM_KEY_VALUE)->key();
		$this->assertTrue(is_string($key));
		return $key;
	}
	
	/**
	 * @depends testHeader
	 * @depends testPayload
	 * @depends testKey
	 *
	 * @param string $header
	 * @param string $payload
	 * @param string $key
	 */
	public function testSign($header, $payload, $key) {
		static $expected = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
		$algo = new HS256Algorithm($key);
		$data = "$header.$payload";
		$signature = $algo->computeSignature($data);
		$this->assertEquals($expected, Base64::urlEncode($signature));
	}
}
