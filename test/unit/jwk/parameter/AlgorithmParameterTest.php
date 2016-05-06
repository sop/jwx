<?php

use JWX\JWA\JWA;
use JWX\JWK\Parameter\AlgorithmParameter;
use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;


/**
 * @group jwk
 * @group parameter
 */
class JWKAlgorithmParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = new AlgorithmParameter(JWA::ALGO_A128CBC_HS256);
		$this->assertInstanceOf(AlgorithmParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWKParameter $param) {
		$this->assertEquals(RegisteredJWKParameter::PARAM_ALGORITHM, 
			$param->name());
	}
}
