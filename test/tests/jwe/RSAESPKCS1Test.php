<?php

use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\RSAESPKCS1Algorithm;
use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use CryptoUtil\PEM\PEM;


/**
 * @group jwe
 */
class RSAESPKCS1Test extends PHPUnit_Framework_TestCase
{
	const PAYLOAD = "PAYLOAD";
	
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
	
	/**
	 *
	 * @return JWE
	 */
	public function testEncryptA128() {
		$key_algo = RSAESPKCS1Algorithm::fromPublicKey(self::$_publicKey);
		$enc_algo = new A128CBCHS256Algorithm();
		$cek = $enc_algo->generateRandomCEK();
		$jwe = JWE::encrypt(self::PAYLOAD, $cek, $key_algo, $enc_algo);
		$this->assertInstanceOf(JWE::class, $jwe);
		return $jwe;
	}
	
	/**
	 * @depends testEncryptA128
	 *
	 * @param JWE $jwe
	 * @return string
	 */
	public function testToCompact(JWE $jwe) {
		$data = $jwe->toCompact();
		$this->assertTrue(is_string($data));
		return $data;
	}
	
	/**
	 * @depends testToCompact
	 *
	 * @param string $data
	 */
	public function testFromCompact($data) {
		$jwe = JWE::fromCompact($data);
		$this->assertInstanceOf(JWE::class, $jwe);
		return $jwe;
	}
	
	/**
	 * @depends testFromCompact
	 *
	 * @param JWE $jwe
	 */
	public function testDecryptA128(JWE $jwe) {
		$key_algo = RSAESPKCS1Algorithm::fromPrivateKey(self::$_privateKey);
		$enc_algo = new A128CBCHS256Algorithm();
		$payload = $jwe->decrypt($key_algo, $enc_algo);
		$this->assertEquals(self::PAYLOAD, $payload);
	}
}