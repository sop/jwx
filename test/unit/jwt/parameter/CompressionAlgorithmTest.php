<?php

use JWX\JWA\JWA;
use JWX\JWE\CompressionAlgorithm\DeflateAlgorithm;
use JWX\JWT\Parameter\CompressionAlgorithmParameter;
use JWX\JWT\Parameter\JWTParameter;


/**
 * @group jwt
 * @group parameter
 */
class CompressionAlgorithmParameterTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$param = new CompressionAlgorithmParameter(JWA::ALGO_DEFLATE);
		$this->assertInstanceOf(CompressionAlgorithmParameter::class, $param);
		return $param;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKParameter $param
	 */
	public function testParamName(JWTParameter $param) {
		$this->assertEquals(JWTParameter::PARAM_COMPRESSION_ALGORITHM, 
			$param->name());
	}
	
	public function testFromAlgo() {
		$param = CompressionAlgorithmParameter::fromAlgorithm(
			new DeflateAlgorithm());
		$this->assertInstanceOf(CompressionAlgorithmParameter::class, $param);
	}
}
