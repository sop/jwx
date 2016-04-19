<?php

use JWX\JWK\RSA\RSAPublicKeyJWK;


class CookbookRSAPublicKeyTest extends PHPUnit_Framework_TestCase
{
	public function testJWK() {
		$json = file_get_contents(COOKBOOK_DIR . "/jwk/3_3.rsa_public_key.json");
		$jwk = RSAPublicKeyJWK::fromJSON($json);
		$this->assertInstanceOf(RSAPublicKeyJWK::class, $jwk);
	}
}
