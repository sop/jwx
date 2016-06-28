<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\KeyTypeParameter;


/**
 * @group jwk
 * @group parameter
 */
class KeyTypeParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = new KeyTypeParameter(KeyTypeParameter::TYPE_OCT);
		$this->assertInstanceOf(KeyTypeParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWKParameter $param) {
		$this->assertEquals(JWKParameter::PARAM_KEY_TYPE, $param->name());
	}
}
