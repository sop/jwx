<?php

use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\AlgorithmParameter;
use JWX\JWK\Parameter\KeyTypeParameter;
use JWX\JWK\Parameter\KeyValueParameter;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWS\Algorithm\HMACAlgorithm;


/**
 * @group jws
 * @group hmac
 */
class HMACAlgorithmTest extends PHPUnit_Framework_TestCase
{
	public function testFromJWK() {
		$jwk = new JWK(new AlgorithmParameter(JWA::ALGO_HS256), 
			new KeyTypeParameter(KeyTypeParameter::TYPE_OCT), 
			new KeyValueParameter("key"));
		$algo = HMACAlgorithm::fromJWK($jwk);
		$this->assertInstanceOf(HMACAlgorithm::class, $algo);
	}
	
	public function testFromJWKExplicitAlgo() {
		$jwk = SymmetricKeyJWK::fromKey("key");
		$algo = HMACAlgorithm::fromJWK($jwk, JWA::ALGO_HS256);
		$this->assertInstanceOf(HMACAlgorithm::class, $algo);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromJWKUnsupportedAlgo() {
		$jwk = SymmetricKeyJWK::fromKey("key");
		HMACAlgorithm::fromJWK($jwk, "nope");
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromJWKMissingAlgo() {
		$jwk = SymmetricKeyJWK::fromKey("key");
		HMACAlgorithm::fromJWK($jwk);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testComputeFails() {
		$algo = new HMACAlgorithmTest_InvalidAlgo("key");
		$algo->computeSignature("data");
	}
}


class HMACAlgorithmTest_InvalidAlgo extends HMACAlgorithm
{
	protected function _hashAlgo() {
		return "nope";
	}
	
	public function algorithmParamValue() {
		return $this->_hashAlgo();
	}
}
