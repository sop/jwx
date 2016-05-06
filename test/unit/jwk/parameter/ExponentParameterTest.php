<?php

use JWX\JWK\Parameter\ExponentParameter;
use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;


/**
 * @group jwk
 * @group parameter
 */
class ExponentParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = ExponentParameter::fromNumber(123);
		$this->assertInstanceOf(ExponentParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWKParameter $param) {
		$this->assertEquals(RegisteredJWKParameter::PARAM_EXPONENT, 
			$param->name());
	}
}
