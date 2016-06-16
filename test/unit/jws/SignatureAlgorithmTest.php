<?php

use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWS\SignatureAlgorithm;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;


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
	}
}
