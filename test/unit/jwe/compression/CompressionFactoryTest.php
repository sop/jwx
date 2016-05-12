<?php

use JWX\JWA\JWA;
use JWX\JWE\CompressionAlgorithm\CompressionFactory;
use JWX\JWE\CompressionAlgorithm;


/**
 * @group jwe
 * @group compression
 */
class CompressionFactoryTest extends PHPUnit_Framework_TestCase
{
	public function testGetAlgo() {
		$algo = CompressionFactory::algoByName(JWA::ALGO_DEFLATE);
		$this->assertInstanceOf(CompressionAlgorithm::class, $algo);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testUnsupportedAlgo() {
		CompressionFactory::algoByName("nope");
	}
}
