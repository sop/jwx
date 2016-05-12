<?php

use JWX\JWK\JWK;
use JWX\JWT\Parameter\JSONWebKeyParameter;
use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;


/**
 * @group jwt
 * @group parameter
 */
class JSONWebKeyParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = new JSONWebKeyParameter(new JWK());
		$this->assertInstanceOf(JSONWebKeyParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWTParameter $param) {
		$this->assertEquals(RegisteredJWTParameter::PARAM_JSON_WEB_KEY, 
			$param->name());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testFromJSONValue(JWTParameter $param) {
		$param = JSONWebKeyParameter::fromJSONValue($param->value());
		$this->assertInstanceOf(JSONWebKeyParameter::class, $param);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JSONWebKeyParameter $param
	 */
	public function testJWK(JSONWebKeyParameter $param) {
		$jwk = $param->jwk();
		$this->assertInstanceOf(JWK::class, $jwk);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromJSONFail() {
		JSONWebKeyParameter::fromJSONValue(null);
	}
}
