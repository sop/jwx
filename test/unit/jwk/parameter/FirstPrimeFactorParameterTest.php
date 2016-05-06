<?php

use JWX\JWK\Parameter\FirstPrimeFactorParameter;
use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;


/**
 * @group jwk
 * @group parameter
 */
class FirstPrimeFactorParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = FirstPrimeFactorParameter::fromNumber(123);
		$this->assertInstanceOf(FirstPrimeFactorParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWKParameter $param) {
		$this->assertEquals(RegisteredJWKParameter::PARAM_FIRST_PRIME_FACTOR, 
			$param->name());
	}
}
