<?php

use JWX\JWA\JWA;
use JWX\JWE\ContentEncryptionAlgorithm;
use JWX\JWE\EncryptionAlgorithm\EncryptionFactory;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\EncryptionAlgorithmParameter;


/**
 * @group jwe
 * @group encryption
 */
class EncryptionFactoryTest extends PHPUnit_Framework_TestCase
{
	public function testAlgoByName() {
		$algo = EncryptionFactory::algoByName(JWA::ALGO_A128CBC_HS256);
		$this->assertInstanceOf(ContentEncryptionAlgorithm::class, $algo);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testAlgoByNameFail() {
		EncryptionFactory::algoByName("nope");
	}
	
	public function testAlgoByHeader() {
		$header = new Header(new EncryptionAlgorithmParameter(JWA::ALGO_A128GCM));
		$algo = EncryptionFactory::algoByHeader($header);
		$this->assertInstanceOf(ContentEncryptionAlgorithm::class, $algo);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testAlgoByHeaderFail() {
		EncryptionFactory::algoByHeader(new Header());
	}
}
