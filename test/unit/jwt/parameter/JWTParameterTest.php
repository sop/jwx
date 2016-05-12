<?php

use JWX\JWT\Parameter\JWTParameter;


/**
 * @group jwt
 * @group parameter
 */
class JWTParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreateUnknown() {
		$param = JWTParameter::fromNameAndValue("unknown", "value");
		$this->assertInstanceOf(JWTParameter::class, $param);
	}
}
