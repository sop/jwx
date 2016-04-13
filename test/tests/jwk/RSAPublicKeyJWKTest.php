<?php

use CryptoUtil\PEM\PEM;
use JWX\JWK\RSA\RSAPublicKeyJWK;


/**
 * @group jwk
 */
class RSAPublicKeyJWKTest extends PHPUnit_Framework_TestCase
{
	public function testFromPEM() {
		$pem = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
		$jwk = RSAPublicKeyJWK::fromPEM($pem);
		$this->assertInstanceOf(RSAPublicKeyJWK::class, $jwk);
		return $jwk;
	}
	
	/**
	 * @depends testFromPEM
	 *
	 * @param RSAPublicKeyJWK $jwk
	 */
	public function testToPEM(RSAPublicKeyJWK $jwk) {
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
		$ref = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/rsa_public_key.pem");
		$this->assertEquals($ref, $pem);
	}
}
