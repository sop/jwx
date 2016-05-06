<?php

use JWX\JWT\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\Util\Base64;
use JWX\JWT\Claims;
use JWX\JWT\Claim\IssuerClaim;
use JWX\JWT\Claim\ExpirationTimeClaim;
use JWX\JWT\Claim\Claim;


/**
 * Test case for rfc7519 section 6.1.
 * Example Unsecured JWT
 *
 * @group example
 *
 * @link https://tools.ietf.org/html/rfc7519#section-6.1
 */
class UnsecuredJWTTest extends PHPUnit_Framework_TestCase
{
	// @formatter:off
	private static $_expectedClaims = 
		'{"iss":"joe",' . "\r\n" .
		' "exp":1300819380,' . "\r\n" .
		' "http://example.com/is_root":true}'
	;// @formatter:on
	

	/**
	 * Test that we're able to produce correct header
	 *
	 * @return Header
	 */
	public function testHeader() {
		static $expected = '{"alg":"none"}';
		$header = new Header(new AlgorithmParameter("none"));
		$this->assertEquals($expected, $header->toJSON());
		return $header;
	}
	
	/**
	 * Test that header encoding is correct
	 *
	 * @depends testHeader
	 *
	 * @param Header $header
	 */
	public function testEncodedHeader(Header $header) {
		static $expected = 'eyJhbGciOiJub25lIn0';
		$this->assertEquals($expected, Base64::urlEncode($header->toJSON()));
	}
	
	/**
	 * Test that we're able to produce correct claims set.
	 *
	 * Claims in the example contains whitespace, which is valid in JSON,
	 * so we have to recode the example claims set to produce normalized
	 * string for comparison.
	 *
	 * @return Claims
	 */
	public function testClaims() {
		$claims = new Claims(new IssuerClaim("joe"), 
			new ExpirationTimeClaim(1300819380), 
			new Claim("http://example.com/is_root", true));
		// normalize example claims
		$expected = Claims::fromJSON(self::$_expectedClaims)->toJSON();
		$this->assertEquals($expected, $claims->toJSON());
		return $claims;
	}
	
	/**
	 * Test that claims encoding is correct
	 *
	 * @depends testClaims
	 *
	 * @param Claims $claims
	 */
	public function testEncodedClaims(Claims $claims) {
		static $expected = <<<EOF
eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
EOF;
		$str = str_replace(["\r","\n"], "", $expected);
		$this->assertEquals($str, Base64::urlEncode(self::$_expectedClaims));
	}
}
