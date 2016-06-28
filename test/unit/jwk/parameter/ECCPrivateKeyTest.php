<?php

use JWX\JWK\Parameter\ECCPrivateKeyParameter;
use JWX\JWK\Parameter\JWKParameter;


/**
 * @group jwk
 * @group parameter
 */
class ECCPrivateKeyParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = ECCPrivateKeyParameter::fromString("0123456789abcdef");
		$this->assertInstanceOf(ECCPrivateKeyParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWKParameter $param) {
		$this->assertEquals(JWKParameter::PARAM_ECC_PRIVATE_KEY, $param->name());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param ECCPrivateKeyParameter $param
	 */
	public function testPrivateKeyOctets(ECCPrivateKeyParameter $param) {
		$this->assertEquals("0123456789abcdef", $param->privateKeyOctets());
	}
}
