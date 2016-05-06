<?php

use JWX\JWT\Parameter\JWKSetURLParameter;
use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;


/**
 * @group jwt
 * @group parameter
 */
class JWKSetURLParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = new JWKSetURLParameter("https://example.com/");
		$this->assertInstanceOf(JWKSetURLParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWTParameter $param) {
		$this->assertEquals(RegisteredJWTParameter::PARAM_JWK_SET_URL, 
			$param->name());
	}
}
