<?php

use CryptoUtil\PEM\PEM;
use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\AlgorithmParameter;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\JWS\Algorithm\RSASSAPKCS1Algorithm;


/**
 * @group jws
 * @group rsassa
 */
class RSASSAPKCS1AlgorithmTest extends PHPUnit_Framework_TestCase
{
	private static $_privKey;
	
	public static function setUpBeforeClass() {
		self::$_privKey = RSAPrivateKeyJWK::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem"));
	}
	
	public static function tearDownAfterClass() {
		self::$_privKey = null;
	}
	
	public function testFromPrivateKeyJWK() {
		$jwk = self::$_privKey->withParameters(
			new AlgorithmParameter(JWA::ALGO_RS256));
		$algo = RSASSAPKCS1Algorithm::fromJWK($jwk);
		$this->assertInstanceOf(RSASSAPKCS1Algorithm::class, $algo);
		return $algo;
	}
	
	public function testFromPublicKeyJWK() {
		$jwk = self::$_privKey->publicKey()->withParameters(
			new AlgorithmParameter(JWA::ALGO_RS256));
		$algo = RSASSAPKCS1Algorithm::fromJWK($jwk);
		$this->assertInstanceOf(RSASSAPKCS1Algorithm::class, $algo);
		return $algo;
	}
	
	public function testFromJWKExplicitAlgo() {
		$algo = RSASSAPKCS1Algorithm::fromJWK(self::$_privKey, JWA::ALGO_RS256);
		$this->assertInstanceOf(RSASSAPKCS1Algorithm::class, $algo);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromJWKMissingAlgo() {
		RSASSAPKCS1Algorithm::fromJWK(self::$_privKey);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromJWKInvalidAlgo() {
		RSASSAPKCS1Algorithm::fromJWK(self::$_privKey, "nope");
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromJWKInvalidKey() {
		$jwk = new JWK();
		RSASSAPKCS1Algorithm::fromJWK($jwk, JWA::ALGO_RS256);
	}
	
	/**
	 * @depends testFromPublicKeyJWK
	 * @expectedException LogicException
	 *
	 * @param RSASSAPKCS1Algorithm $algo
	 */
	public function testComputeMissingPrivateKey(RSASSAPKCS1Algorithm $algo) {
		$algo->computeSignature("data");
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testComputeFail() {
		$algo = RSASSAPKCS1AlgorithmTest_InvalidMethod::fromPrivateKey(
			self::$_privKey);
		$algo->computeSignature("data");
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testValidateFail() {
		$algo = RSASSAPKCS1AlgorithmTest_InvalidMethod::fromPrivateKey(
			self::$_privKey);
		$algo->validateSignature("data", "");
	}
	
	/**
	 * @depends testFromPrivateKeyJWK
	 * @expectedException RuntimeException
	 *
	 * @param RSASSAPKCS1Algorithm $algo
	 */
	public function testComputeInvalidKey(RSASSAPKCS1Algorithm $algo) {
		$obj = new ReflectionClass($algo);
		$prop = $obj->getProperty("_privateKey");
		$prop->setAccessible(true);
		$prop->setValue($algo, new RSASSAPKCS1AlgorithmTest_KeyMockup());
		$algo->computeSignature("test");
	}
	
	/**
	 * @depends testFromPrivateKeyJWK
	 * @expectedException RuntimeException
	 *
	 * @param RSASSAPKCS1Algorithm $algo
	 */
	public function testValidateInvalidKey(RSASSAPKCS1Algorithm $algo) {
		$obj = new ReflectionClass($algo);
		$prop = $obj->getProperty("_publicKey");
		$prop->setAccessible(true);
		$prop->setValue($algo, new RSASSAPKCS1AlgorithmTest_KeyMockup());
		$algo->validateSignature("test", "");
	}
}


class RSASSAPKCS1AlgorithmTest_InvalidMethod extends RSASSAPKCS1Algorithm
{
	protected function _mdMethod() {
		return "nope";
	}
	
	public function algorithmParamValue() {
		return $this->_mdMethod();
	}
}


class RSASSAPKCS1AlgorithmTest_KeyMockup
{
	public function toPEM() {
		return new RSAESKeyTest_PEMMockup();
	}
}


class RSASSAPKCS1AlgorithmTest_PEMMockup
{
	public function string() {
		return "";
	}
}
