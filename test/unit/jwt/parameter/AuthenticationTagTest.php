<?php

use JWX\JWT\Parameter\AuthenticationTagParameter;
use JWX\JWT\Parameter\JWTParameter;


/**
 * @group jwt
 * @group parameter
 */
class AuthenticationTagParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = AuthenticationTagParameter::fromString("abcdef");
		$this->assertInstanceOf(AuthenticationTagParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWTParameter $param) {
		$this->assertEquals(JWTParameter::PARAM_AUTHENTICATION_TAG, 
			$param->name());
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testCreateFail() {
		new AuthenticationTagParameter("\0");
	}
}
