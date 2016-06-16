<?php

use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWS\SignatureAlgorithm;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\JWTParameter;


/**
 * @group jws
 */
class SignatureAlgorithmTest extends PHPUnit_Framework_TestCase
{
	public function testFromJWK() {
		$jwk = SymmetricKeyJWK::fromKey("test");
		$header = new Header(new AlgorithmParameter(JWA::ALGO_HS256));
		$algo = SignatureAlgorithm::fromJWK($jwk, $header);
		$this->assertInstanceOf(SignatureAlgorithm::class, $algo);
		return $algo;
	}
	
	/**
	 * @depends testFromJWK
	 *
	 * @param SignatureAlgorithm $algo
	 */
	public function testWithKeyID(SignatureAlgorithm $algo) {
		$algo = $algo->withKeyID("id");
		$this->assertInstanceOf(SignatureAlgorithm::class, $algo);
		return $algo;
	}
	
	/**
	 * @depends testWithKeyID
	 *
	 * @param SignatureAlgorithm $algo
	 */
	public function testHeaderParameters(SignatureAlgorithm $algo) {
		$params = $algo->headerParameters();
		$this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
	}
}
