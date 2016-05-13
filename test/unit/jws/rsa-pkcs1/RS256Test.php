<?php

use CryptoUtil\PEM\PEM;
use JWX\JWA\JWA;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\JWS\Algorithm\RS256Algorithm;
use JWX\JWS\Algorithm\RSASSAPKCS1Algorithm;
use JWX\JWS\SignatureAlgorithm;
use JWX\JWT\Parameter\AlgorithmParameterValue;


/**
 * @group jws
 * @group rsassa
 */
class RS256Test extends PHPUnit_Framework_TestCase
{
	private static $_privKey;
	
	const DATA = "CONTENT";
	
	public static function setUpBeforeClass() {
		self::$_privKey = RSAPrivateKeyJWK::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem"));
	}
	
	public static function tearDownAfterClass() {
		self::$_privKey = null;
	}
	
	public function testCreate() {
		$algo = RS256Algorithm::fromPrivateKey(self::$_privKey);
		$this->assertInstanceOf(RSASSAPKCS1Algorithm::class, $algo);
		return $algo;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param AlgorithmParameterValue $algo
	 */
	public function testAlgoParamValue(AlgorithmParameterValue $algo) {
		$this->assertEquals(JWA::ALGO_RS256, $algo->algorithmParamValue());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param SignatureAlgorithm $algo
	 */
	public function testSign(SignatureAlgorithm $algo) {
		$sig = $algo->computeSignature(self::DATA);
		$this->assertInternalType("string", $sig);
		return $sig;
	}
	
	/**
	 * @depends testCreate
	 * @depends testSign
	 *
	 * @param SignatureAlgorithm $algo
	 * @param unknown $signature
	 */
	public function testValidate(SignatureAlgorithm $algo, $signature) {
		$this->assertTrue($algo->validateSignature(self::DATA, $signature));
	}
}
