<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\KeyIDParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;


/**
 * @group jwk
 * @group parameter
 */
class JWKKeyIDParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = new KeyIDParameter("test");
		$this->assertInstanceOf(KeyIDParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWKParameter $param) {
		$this->assertEquals(RegisteredJWKParameter::PARAM_KEY_ID, 
			$param->name());
	}
}
