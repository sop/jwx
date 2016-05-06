<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;
use JWX\JWK\Parameter\SecondPrimeFactorParameter;


/**
 * @group jwk
 * @group parameter
 */
class SecondPrimeFactorParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = SecondPrimeFactorParameter::fromNumber(123);
		$this->assertInstanceOf(SecondPrimeFactorParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWKParameter $param) {
		$this->assertEquals(RegisteredJWKParameter::PARAM_SECOND_PRIME_FACTOR, 
			$param->name());
	}
}
