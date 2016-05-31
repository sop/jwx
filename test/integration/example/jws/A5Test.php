<?php

use JWX\JWS\Algorithm\NoneAlgorithm;
use JWX\JWS\JWS;
use JWX\JWT\Header;
use JWX\JWT\Parameter\RegisteredJWTParameter;
use JWX\Util\Base64;


/**
 * Test case for RFC 7515 appendix A.5.
 * Example Unsecured JWS
 *
 * @group example
 *
 * @link https://tools.ietf.org/html/rfc7515#appendix-A.5
 */
class UnsecuredJWSTest extends PHPUnit_Framework_TestCase
{
	private static $_header = "eyJhbGciOiJub25lIn0";
	
	private static $_payloadBytes = [123, 34, 105, 115, 115, 34, 58, 34, 
		106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 
		48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 
		47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 
		95, 114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125];
	
	private static $_payloadJSON;
	
	public static function setUpBeforeClass() {
		self::$_payloadJSON = implode("", 
			array_map("chr", self::$_payloadBytes));
	}
	
	public static function tearDownAfterClass() {
		self::$_payloadJSON = null;
	}
	
	public function testHeader() {
		$header = Header::fromJSON(Base64::urlDecode(self::$_header));
		$alg = $header->get(RegisteredJWTParameter::P_ALG)->value();
		$this->assertEquals("none", $alg);
	}
	
	public function testPayload() {
		static $expected_data = <<<EOF
eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
EOF;
		$expected = str_replace(["\r", "\n"], "", $expected_data);
		$payload = Base64::urlEncode(self::$_payloadJSON);
		$this->assertEquals($expected, $payload);
		return $payload;
	}
	
	/**
	 * @depends testPayload
	 *
	 * @param string $payload
	 */
	public function testCreateAndValidate($payload) {
		$token = self::$_header . "." . $payload . ".";
		$jws = JWS::fromCompact($token);
		$this->assertTrue($jws->validate(new NoneAlgorithm()));
	}
}
