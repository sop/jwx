<?php

use JWX\JWA\JWA;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWK\JWK;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;


/**
 * @group jwe
 * @group key
 */
class KeyManagementAlgorithmTest extends PHPUnit_Framework_TestCase
{
	public function testFromJWK() {
		$jwk = SymmetricKeyJWK::fromKey("test");
		$header = new Header(new AlgorithmParameter(JWA::ALGO_DIR));
		$algo = KeyManagementAlgorithm::fromJWK($jwk, $header);
		$this->assertInstanceOf(KeyManagementAlgorithm::class, $algo);
	}
}
