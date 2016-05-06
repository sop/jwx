<?php

use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;
use JWX\JWT\Parameter\X509URLParameter;


/**
 * @group jwt
 * @group parameter
 */
class X509URLParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = new X509URLParameter("https://example.com/");
		$this->assertInstanceOf(X509URLParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWTParameter $param) {
		$this->assertEquals(RegisteredJWTParameter::PARAM_X509_URL, 
			$param->name());
	}
}
