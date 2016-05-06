<?php

use JWX\JWK\Parameter\FirstCRTCoefficientParameter;
use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;


/**
 * @group jwk
 * @group parameter
 */
class FirstCRTCoefficientParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = FirstCRTCoefficientParameter::fromNumber(123);
		$this->assertInstanceOf(FirstCRTCoefficientParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWKParameter $param) {
		$this->assertEquals(RegisteredJWKParameter::PARAM_FIRST_CRT_COEFFICIENT, 
			$param->name());
	}
}
