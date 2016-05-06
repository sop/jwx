<?php

use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;
use JWX\JWT\Parameter\X509CertificateChainParameter;


/**
 * @group jwt
 * @group parameter
 */
class X509CertificateChainParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = new X509CertificateChainParameter();
		$this->assertInstanceOf(X509CertificateChainParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWTParameter $param) {
		$this->assertEquals(
			RegisteredJWTParameter::PARAM_X509_CERTIFICATE_CHAIN, $param->name());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testFromJSONValue(JWTParameter $param) {
		$param = X509CertificateChainParameter::fromJSONValue($param->value());
		$this->assertInstanceOf(X509CertificateChainParameter::class, $param);
	}
}
