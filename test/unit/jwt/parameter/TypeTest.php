<?php

use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;
use JWX\JWT\Parameter\TypeParameter;


/**
 * @group jwt
 * @group parameter
 */
class TypeParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = new TypeParameter("example");
		$this->assertInstanceOf(TypeParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWTParameter $param) {
		$this->assertEquals(RegisteredJWTParameter::PARAM_TYPE, $param->name());
	}
}
