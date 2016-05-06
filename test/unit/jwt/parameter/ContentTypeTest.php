<?php

use JWX\JWT\Parameter\ContentTypeParameter;
use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;


/**
 * @group jwt
 * @group parameter
 */
class ContentTypeParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = new ContentTypeParameter("example");
		$this->assertInstanceOf(ContentTypeParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWTParameter $param) {
		$this->assertEquals(RegisteredJWTParameter::PARAM_CONTENT_TYPE, 
			$param->name());
	}
}
