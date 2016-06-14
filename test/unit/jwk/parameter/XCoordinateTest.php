<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;
use JWX\JWK\Parameter\XCoordinateParameter;


/**
 * @group jwk
 * @group parameter
 */
class XCoordinateParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = XCoordinateParameter::fromString("\xff\x88");
		$this->assertInstanceOf(XCoordinateParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWKParameter $param) {
		$this->assertEquals(RegisteredJWKParameter::PARAM_X_COORDINATE, 
			$param->name());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param XCoordinateParameter $param
	 */
	public function testCoordinateOctets(XCoordinateParameter $param) {
		$this->assertEquals("\xff\x88", $param->coordinateOctets());
	}
}
