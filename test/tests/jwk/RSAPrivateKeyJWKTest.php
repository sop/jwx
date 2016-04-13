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
}
