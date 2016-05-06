<?php

use JWX\JWK\Parameter\CurveParameter;
use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;


/**
 * @group jwk
 * @group parameter
 */
class CurveParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = new CurveParameter(CurveParameter::CURVE_P256);
		$this->assertInstanceOf(CurveParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWKParameter $param) {
		$this->assertEquals(RegisteredJWKParameter::PARAM_CURVE, $param->name());
	}
}
