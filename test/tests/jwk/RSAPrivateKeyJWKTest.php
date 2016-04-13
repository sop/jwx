<?php

use CryptoUtil\PEM\PEM;
use JWX\JWK\RSA\RSAPrivateKeyJWK;


/**
 * @group jwk
 */
class RSAPrivateKeyJWKTest extends PHPUnit_Framework_TestCase
{
	public function testFromPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem");
		$jwk = RSAPrivateKeyJWK::fromPEM($pem);
		$this->assertInstanceOf(RSAPrivateKeyJWK::class, $jwk);
		return $jwk;
	}
	
	/**
	 * @depends testFromPEM
	 *
	 * @param RSAPrivateKeyJWK $jwk
	 */
	public function testToPEM(RSAPrivateKeyJWK $jwk) {
		$pem = $jwk->toPEM();
		$this->assertInstanceOf(PEM::class, $pem);
		return $pem;
	}
	
	/**
	 * @depends testToPEM
	 *
	 * @param PEM $pem
	 */
	public function testRecoded(PEM $pem) {
		$ref = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_private_key.pem");
		$this->assertEquals($ref, $pem);
	}
}
