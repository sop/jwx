<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;
use JWX\JWK\Parameter\YCoordinateParameter;


/**
 * @group jwk
 * @group parameter
 */
class YCoordinateParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = YCoordinateParameter::fromString("\xff\x88");
		$this->assertInstanceOf(YCoordinateParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWKParameter $param) {
		$this->assertEquals(RegisteredJWKParameter::PARAM_Y_COORDINATE, 
			$param->name());
	}
}
