<?php

use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\Util\Base64;


/**
 * @group jwk
 */
class SymmetricKeyJWKTest extends PHPUnit_Framework_TestCase
{
	const KEY = "password";
	
	public function testCreate() {
		$jwk = SymmetricKeyJWK::fromArray(
			array("kty" => "oct", "k" => Base64::urlEncode(self::KEY)));
		$this->assertInstanceOf(SymmetricKeyJWK::class, $jwk);
		return $jwk;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param SymmetricKeyJWK $jwk
	 */
	public function testKey(SymmetricKeyJWK $jwk) {
		$this->assertEquals(self::KEY, $jwk->key());
	}
}
