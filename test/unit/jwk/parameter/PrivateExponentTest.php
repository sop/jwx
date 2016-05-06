<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\PrivateExponentParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;


/**
 * @group jwk
 * @group parameter
 */
class PrivateExponentParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = PrivateExponentParameter::fromNumber(123);
		$this->assertInstanceOf(PrivateExponentParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWKParameter $param) {
		$this->assertEquals(RegisteredJWKParameter::PARAM_PRIVATE_EXPONENT, 
			$param->name());
	}
}
