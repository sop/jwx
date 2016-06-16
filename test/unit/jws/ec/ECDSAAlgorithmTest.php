<?php

use CryptoUtil\PEM\PEM;
use JWX\JWA\JWA;
use JWX\JWK\EC\ECPrivateKeyJWK;
use JWX\JWK\EC\ECPublicKeyJWK;
use JWX\JWK\RSA\RSAPublicKeyJWK;
use JWX\JWS\Algorithm\ECDSAAlgorithm;
use JWX\JWS\Algorithm\ES384Algorithm;
use JWX\JWS\Algorithm\ES512Algorithm;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\JWTParameter;


/**
 * @group jws
 * @group ec
 */
class ECDSAAlgorithmTest extends PHPUnit_Framework_TestCase
{
	private static $_jwk;
	
	public static function setUpBeforeClass() {
		self::$_jwk = ECPublicKeyJWK::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/ec/public_key_P-521.pem"));
	}
	
	public static function tearDownAfterClass() {
		self::$_jwk = null;
	}
	/**
	 * @expectedException InvalidArgumentException
	 */
	public function testInvalidCurve() {
		ES384Algorithm::fromPublicKey(self::$_jwk);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidSignatureLength() {
		$algo = ES512Algorithm::fromPublicKey(self::$_jwk);
		$algo->validateSignature("test", "");
	}
	
	public function testHeaderParameters() {
		$algo = ES512Algorithm::fromPublicKey(self::$_jwk);
		$params = $algo->headerParameters();
		$this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
	}
	
	public function testFromPublicKeyJWK() {
		$header = new Header(new AlgorithmParameter(JWA::ALGO_ES512));
		$algo = ECDSAAlgorithm::fromJWK(self::$_jwk, $header);
		$this->assertInstanceOf(ES512Algorithm::class, $algo);
	}
	
	public function testFromPrivateKeyJWK() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/ec/private_key_P-521.pem");
		$jwk = ECPrivateKeyJWK::fromPEM($pem);
		$header = new Header(new AlgorithmParameter(JWA::ALGO_ES512));
		$algo = ECDSAAlgorithm::fromJWK($jwk, $header);
		$this->assertInstanceOf(ES512Algorithm::class, $algo);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromJWKUnsupportedAlgo() {
		$header = new Header(new AlgorithmParameter(JWA::ALGO_HS512));
		ECDSAAlgorithm::fromJWK(self::$_jwk, $header);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromJWKWrongType() {
		$jwk = RSAPublicKeyJWK::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem"));
		$header = new Header(new AlgorithmParameter(JWA::ALGO_ES256));
		ECDSAAlgorithm::fromJWK($jwk, $header);
	}
}
