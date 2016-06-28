<?php

use JWX\JWK\Parameter\FirstFactorCRTExponentParameter;
use JWX\JWK\Parameter\JWKParameter;


/**
 * @group jwk
 * @group parameter
 */
class FirstFactorCRTExponentParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = FirstFactorCRTExponentParameter::fromNumber(123);
		$this->assertInstanceOf(FirstFactorCRTExponentParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWKParameter $param) {
		$this->assertEquals(JWKParameter::PARAM_FIRST_FACTOR_CRT_EXPONENT, 
			$param->name());
	}
}
