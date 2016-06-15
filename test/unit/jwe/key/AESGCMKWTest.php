<?php

use JWX\JWA\JWA;
use JWX\JWE\KeyAlgorithm\A128GCMKWAlgorithm;
use JWX\JWE\KeyAlgorithm\AESGCMKWAlgorithm;
use JWX\JWK\JWK;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\InitializationVectorParameter;
use JWX\JWT\Parameter\JWTParameter;


/**
 * @group jwe
 * @group key
 */
class AESGCMKWTest extends PHPUnit_Framework_TestCase
{
	const KEY_128 = "123456789 123456";
	
	const IV = "123456789 12";
	
	public function testHeaderParams() {
		$algo = new A128GCMKWAlgorithm(self::KEY_128, self::IV);
		$params = $algo->headerParameters();
		$this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
	}
	
	/**
	 * @expectedException LengthException
	 */
	public function testInvalidIVFail() {
		new A128GCMKWAlgorithm(self::KEY_128, "fail");
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testDecryptMissingAuthTag() {
		$algo = new A128GCMKWAlgorithm(self::KEY_128, self::IV);
		$algo->decrypt("");
	}
	
	public function testFromJWK() {
		$jwk = SymmetricKeyJWK::fromKey(self::KEY_128);
		$header = new Header(new AlgorithmParameter(JWA::ALGO_A128GCMKW), 
			InitializationVectorParameter::fromString(self::IV));
		$algo = AESGCMKWAlgorithm::fromJWK($jwk, $header);
		$this->assertInstanceOf(A128GCMKWAlgorithm::class, $algo);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromJWKNoAlgo() {
		$jwk = SymmetricKeyJWK::fromKey(self::KEY_128);
		$header = new Header(InitializationVectorParameter::fromString(self::IV));
		AESGCMKWAlgorithm::fromJWK($jwk, $header);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromJWKNoIV() {
		$jwk = SymmetricKeyJWK::fromKey(self::KEY_128);
		$header = new Header(new AlgorithmParameter(JWA::ALGO_A128GCMKW));
		AESGCMKWAlgorithm::fromJWK($jwk, $header);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromJWKUnsupportedAlgo() {
		$jwk = SymmetricKeyJWK::fromKey(self::KEY_128);
		$header = new Header(InitializationVectorParameter::fromString(self::IV), 
			new AlgorithmParameter(JWA::ALGO_NONE));
		AESGCMKWAlgorithm::fromJWK($jwk, $header);
	}
}
