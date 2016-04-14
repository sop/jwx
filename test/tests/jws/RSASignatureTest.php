<?php

use JWX\JWS\JWS;
use JWX\JWS\Algorithm\RS256Algorithm;
use JWX\JWS\Algorithm\RS384Algorithm;
use JWX\JWS\Algorithm\RS512Algorithm;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use CryptoUtil\PEM\PEM;


/**
 * @group jws
 */
class RSASignatureTest extends PHPUnit_Framework_TestCase
{
	const PAYLOAD = "PAYLOAD";
	
	private static $_privateKey;
	
	private static $_publicKey;
	
	public static function setUpBeforeClass() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem");
		self::$_privateKey = RSAPrivateKeyJWK::fromPEM($pem);
		self::$_publicKey = self::$_privateKey->publicKey();
	}
	
	public static function tearDownAfterClass() {
		self::$_privateKey = null;
		self::$_publicKey = null;
	}
	
	public function testSignRS256() {
		$algo = RS256Algorithm::fromPrivateKey(self::$_privateKey);
		$jws = JWS::sign(self::PAYLOAD, $algo);
		$this->assertInstanceOf(JWS::class, $jws);
		return $jws;
	}
	
	/**
	 * @depends testSignRS256
	 *
	 * @param JWS $jws
	 */
	public function testValidateRS256(JWS $jws) {
		$algo = RS256Algorithm::fromPublicKey(self::$_publicKey);
		$this->assertTrue($jws->validate($algo));
	}
	
	public function testSignRS384() {
		$algo = RS384Algorithm::fromPrivateKey(self::$_privateKey);
		$jws = JWS::sign(self::PAYLOAD, $algo);
		$this->assertInstanceOf(JWS::class, $jws);
		return $jws;
	}
	
	/**
	 * @depends testSignRS384
	 *
	 * @param JWS $jws
	 */
	public function testValidateRS384(JWS $jws) {
		$algo = RS384Algorithm::fromPublicKey(self::$_publicKey);
		$this->assertTrue($jws->validate($algo));
	}
	
	public function testSignRS512() {
		$algo = RS512Algorithm::fromPrivateKey(self::$_privateKey);
		$jws = JWS::sign(self::PAYLOAD, $algo);
		$this->assertInstanceOf(JWS::class, $jws);
		return $jws;
	}
	
	/**
	 * @depends testSignRS512
	 *
	 * @param JWS $jws
	 */
	public function testValidateRS512(JWS $jws) {
		$algo = RS512Algorithm::fromPublicKey(self::$_publicKey);
		$this->assertTrue($jws->validate($algo));
	}
}
