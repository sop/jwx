<?php

use CryptoUtil\PEM\PEM;
use JWX\JWA\JWA;
use JWX\JWK\EC\ECPrivateKeyJWK;
use JWX\JWS\Algorithm\ECDSAAlgorithm;
use JWX\JWS\Algorithm\ES256Algorithm;
use JWX\JWS\SignatureAlgorithm;
use JWX\JWT\Parameter\AlgorithmParameterValue;


/**
 * @group jws
 * @group ec
 */
class ES256Test extends PHPUnit_Framework_TestCase
{
	const DATA = "CONTENT";
	
	private static $_jwk;
	
	public static function setUpBeforeClass() {
		self::$_jwk = ECPrivateKeyJWK::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/ec/private_key_P-256.pem"));
	}
	
	public static function tearDownAfterClass() {
		self::$_jwk = null;
	}
	
	public function testCreate() {
		$algo = ES256Algorithm::fromPrivateKey(self::$_jwk);
		$this->assertInstanceOf(ECDSAAlgorithm::class, $algo);
		return $algo;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AlgorithmParameterValue $algo
	 */
	public function testAlgoParamValue(AlgorithmParameterValue $algo) {
		$this->assertEquals(JWA::ALGO_ES256, $algo->algorithmParamValue());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param SignatureAlgorithm $algo
	 */
	public function testSign(SignatureAlgorithm $algo) {
		$sig = $algo->computeSignature(self::DATA);
		$this->assertEquals(64, strlen($sig));
		return $sig;
	}
	
	/**
	 * @depends testCreate
	 * @depends testSign
	 *
	 * @param SignatureAlgorithm $algo
	 * @param string $signature
	 */
	public function testValidate(SignatureAlgorithm $algo, $signature) {
		$this->assertTrue($algo->validateSignature(self::DATA, $signature));
	}
}
