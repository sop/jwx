<?php

use JWX\JWA\JWA;
use JWX\JWE\CompressionAlgorithm\CompressionFactory;
use JWX\JWE\CompressionAlgorithm;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\CompressionAlgorithmParameter;


/**
 * @group jwe
 * @group compression
 */
class CompressionFactoryTest extends PHPUnit_Framework_TestCase
{
	public function testAlgoByName() {
		$algo = CompressionFactory::algoByName(JWA::ALGO_DEFLATE);
		$this->assertInstanceOf(CompressionAlgorithm::class, $algo);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testUnsupportedAlgo() {
		CompressionFactory::algoByName("nope");
	}
	
	public function testAlgoByHeader() {
		$header = new Header(
			new CompressionAlgorithmParameter(JWA::ALGO_DEFLATE));
		$algo = CompressionFactory::algoByHeader($header);
		$this->assertInstanceOf(CompressionAlgorithm::class, $algo);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testAlogByHeaderMissingParam() {
		CompressionFactory::algoByHeader(new Header());
	}
}
