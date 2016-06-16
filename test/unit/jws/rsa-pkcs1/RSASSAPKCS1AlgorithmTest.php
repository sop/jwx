<?php

use CryptoUtil\PEM\PEM;
use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\JWS\Algorithm\RSASSAPKCS1Algorithm;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\JWTParameter;


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
		$header = new Header(new AlgorithmParameter(JWA::ALGO_RS256));
		$algo = RSASSAPKCS1Algorithm::fromJWK(self::$_privKey, $header);
		$this->assertInstanceOf(RSASSAPKCS1Algorithm::class, $algo);
		return $algo;
	}
	
	public function testFromPublicKeyJWK() {
		$header = new Header(new AlgorithmParameter(JWA::ALGO_RS256));
		$algo = RSASSAPKCS1Algorithm::fromJWK(self::$_privKey->publicKey(), 
			$header);
		$this->assertInstanceOf(RSASSAPKCS1Algorithm::class, $algo);
		return $algo;
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromJWKInvalidAlgo() {
		$header = new Header(new AlgorithmParameter(JWA::ALGO_ES256));
		RSASSAPKCS1Algorithm::fromJWK(self::$_privKey, $header);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromJWKInvalidKey() {
		$jwk = new JWK();
		$header = new Header(new AlgorithmParameter(JWA::ALGO_RS256));
		RSASSAPKCS1Algorithm::fromJWK($jwk, $header);
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
	
	/**
	 * @depends testFromPublicKeyJWK
	 *
	 * @param RSASSAPKCS1Algorithm $algo
	 */
	public function testHeaderParameters(RSASSAPKCS1Algorithm $algo) {
		$params = $algo->headerParameters();
		$this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
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
