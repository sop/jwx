<?php

use JWX\JWT\Parameter\AuthenticationTagParameter;
use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;


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
		$this->assertEquals(RegisteredJWTParameter::PARAM_AUTHENTICATION_TAG, 
			$param->name());
	}
}
