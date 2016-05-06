<?php

use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;
use JWX\JWT\Parameter\X509CertificateSHA256ThumbprintParameter;


/**
 * @group jwt
 * @group parameter
 */
class X509CertificateSHA256ThumbprintParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = X509CertificateSHA256ThumbprintParameter::fromString("abcdef");
		$this->assertInstanceOf(X509CertificateSHA256ThumbprintParameter::class, 
			$param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWTParameter $param) {
		$this->assertEquals(
			RegisteredJWTParameter::PARAM_X509_CERTIFICATE_SHA256_THUMBPRINT, 
			$param->name());
	}
}
