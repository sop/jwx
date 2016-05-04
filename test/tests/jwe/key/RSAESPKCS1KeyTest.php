<?php

use CryptoUtil\PEM\PEM;
use JWX\JWA\JWA;
use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\RSAESKeyAlgorithm;
use JWX\JWE\KeyAlgorithm\RSAESPKCS1Algorithm;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWK\RSA\RSAPrivateKeyJWK;


/**
 * @group jwe
 * @group key
 */
class RSAESPKCS1KeyTest extends PHPUnit_Framework_TestCase
{
	const CEK = "123456789 123456";
	
	private static $_publicKey;
	
	private static $_privateKey;
	
	public static function setUpBeforeClass() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem");
		self::$_privateKey = RSAPrivateKeyJWK::fromPEM($pem);
		self::$_publicKey = self::$_privateKey->publicKey();
	}
	
	public static function tearDownAfterClass() {
		self::$_publicKey = null;
		self::$_privateKey = null;
	}
	
	public function testCreate() {
		$algo = RSAESPKCS1Algorithm::fromPrivateKey(self::$_privateKey);
		$this->assertInstanceOf(RSAESKeyAlgorithm::class, $algo);
		return $algo;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param KeyManagementAlgorithm $algo
	 */
	public function testAlgoValue(KeyManagementAlgorithm $algo) {
		$this->assertEquals(JWA::ALGO_RSA1_5, $algo->algorithmParamValue());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param RSAESKeyAlgorithm $algo
	 */
	public function testEncrypt(RSAESKeyAlgorithm $algo) {
		$data = $algo->encrypt(self::CEK);
		$this->assertNotEquals(self::CEK, $data);
		return $data;
	}
	
	/**
	 * @depends testCreate
	 * @depends testEncrypt
	 *
	 * @param RSAESKeyAlgorithm $algo
	 * @param string $data
	 */
	public function testDecrypt(RSAESKeyAlgorithm $algo, $data) {
		$cek = $algo->decrypt($data);
		$this->assertEquals(self::CEK, $cek);
	}
}
