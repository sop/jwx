<?php

use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\KeyIDParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;


/**
 * @group jwt
 * @group parameter
 */
class JWTKeyIDParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = new KeyIDParameter(false);
		$this->assertInstanceOf(KeyIDParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWTParameter $param) {
		$this->assertEquals(RegisteredJWTParameter::PARAM_KEY_ID, 
			$param->name());
	}
}
