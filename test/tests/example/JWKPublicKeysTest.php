<?php

use JWX\JWK\JWK;
use JWX\JWK\JWKSet;
use JWX\JWK\Parameter\RegisteredJWKParameter;


/**
 * Test case for rfc7517 appendix A.1.
 * Example Public Keys
 *
 * @group example
 *
 * @link https://tools.ietf.org/html/rfc7517#appendix-A.1
 */
class JWKPublicKeysTest extends PHPUnit_Framework_TestCase
{
	private static $_data = <<<EOF
{"keys":
  [
    {"kty":"EC",
     "crv":"P-256",
     "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
     "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
     "use":"enc",
     "kid":"1"},

    {"kty":"RSA",
     "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
     "e":"AQAB",
     "alg":"RS256",
     "kid":"2011-04-29"}
  ]
}
EOF;
	
	public function testJWKSet() {
		$jwkset = JWKSet::fromJSON(self::$_data);
		$this->assertInstanceOf(JWKSet::class, $jwkset);
		return $jwkset;
	}
	
	/**
	 * @depends testJWKSet
	 *
	 * @param JWKSet $jwkset
	 */
	public function testKeyCount(JWKSet $jwkset) {
		$this->assertCount(2, $jwkset);
	}
	
	/**
	 * @depends testJWKSet
	 *
	 * @param JWKSet $jwkset
	 */
	public function testKey1(JWKSet $jwkset) {
		$jwk = $jwkset->byKeyID("1");
		$this->assertInstanceOf(JWK::class, $jwk);
		return $jwk;
	}
	
	/**
	 * @depends testJWKSet
	 *
	 * @param JWKSet $jwkset
	 */
	public function testKey2(JWKSet $jwkset) {
		$jwk = $jwkset->byKeyID("2011-04-29");
		$this->assertInstanceOf(JWK::class, $jwk);
		return $jwk;
	}
	
	/**
	 * @depends testKey1
	 *
	 * @param JWK $jwk
	 */
	public function testKey1Type(JWK $jwk) {
		$this->assertEquals("EC", 
			$jwk->get(RegisteredJWKParameter::PARAM_KEY_TYPE)
				->value());
	}
	
	/**
	 * @depends testKey1
	 *
	 * @param JWK $jwk
	 */
	public function testKey1Use(JWK $jwk) {
		$this->assertEquals("enc", 
			$jwk->get(RegisteredJWKParameter::PARAM_PUBLIC_KEY_USE)
				->value());
	}
	
	/**
	 * @depends testKey2
	 *
	 * @param JWK $jwk
	 */
	public function testKey2Type(JWK $jwk) {
		$this->assertEquals("RSA", 
			$jwk->get(RegisteredJWKParameter::PARAM_KEY_TYPE)
				->value());
	}
	
	/**
	 * @depends testKey2
	 *
	 * @param JWK $jwk
	 */
	public function testKey2Algo(JWK $jwk) {
		$this->assertEquals("RS256", 
			$jwk->get(RegisteredJWKParameter::PARAM_ALGORITHM)
				->value());
	}
}
