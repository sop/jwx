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
}
