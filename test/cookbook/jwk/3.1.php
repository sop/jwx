<?php

use JWX\JWK\EC\ECPublicKeyJWK;


class CookbookECPublicKeyTest extends PHPUnit_Framework_TestCase
{
	public function testJWK() {
		$json = file_get_contents(COOKBOOK_DIR . "/jwk/3_1.ec_public_key.json");
		$jwk = ECPublicKeyJWK::fromJSON($json);
		$this->assertInstanceOf(ECPublicKeyJWK::class, $jwk);
	}
}
