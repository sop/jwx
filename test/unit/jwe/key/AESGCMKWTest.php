<?php

use JWX\JWA\JWA;
use JWX\JWE\KeyAlgorithm\A128GCMKWAlgorithm;
use JWX\JWE\KeyAlgorithm\AESGCMKWAlgorithm;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\AlgorithmParameter;
use JWX\JWK\Parameter\KeyTypeParameter;
use JWX\JWK\Parameter\KeyValueParameter;
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
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromJWKNoAlgo() {
		$jwk = new JWK(new KeyTypeParameter(KeyTypeParameter::TYPE_OCT), 
			KeyValueParameter::fromString(self::KEY_128));
		AESGCMKWAlgorithm::fromJWK($jwk, self::IV);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromJWKUnsupportedAlgo() {
		$jwk = new JWK(new AlgorithmParameter(JWA::ALGO_NONE), 
			new KeyTypeParameter(KeyTypeParameter::TYPE_OCT), 
			KeyValueParameter::fromString(self::KEY_128));
		AESGCMKWAlgorithm::fromJWK($jwk, self::IV);
	}
}
