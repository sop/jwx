<?php

use JWX\JWA\JWA;
use JWX\JWE\ContentEncryptionAlgorithm;
use JWX\JWE\EncryptionAlgorithm\EncryptionAlgorithmFactory;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\EncryptionAlgorithmParameter;


/**
 * @group jwe
 * @group encryption
 */
class EncryptionFactoryTest extends PHPUnit_Framework_TestCase
{
	public function testAlgoByName() {
		$algo = EncryptionAlgorithmFactory::algoByName(JWA::ALGO_A128CBC_HS256);
		$this->assertInstanceOf(ContentEncryptionAlgorithm::class, $algo);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testAlgoByNameFail() {
		EncryptionAlgorithmFactory::algoByName("nope");
	}
	
	public function testAlgoByHeader() {
		$header = new Header(new EncryptionAlgorithmParameter(JWA::ALGO_A128GCM));
		$algo = EncryptionAlgorithmFactory::algoByHeader($header);
		$this->assertInstanceOf(ContentEncryptionAlgorithm::class, $algo);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testAlgoByHeaderFail() {
		EncryptionAlgorithmFactory::algoByHeader(new Header());
	}
}
