<?php

use JWX\JWK\RSA\RSAPrivateKeyJWK;

class CookbookRSAPrivateKeyTest extends PHPUnit_Framework_TestCase
{
    public function testJWK()
    {
        $json = file_get_contents(
            COOKBOOK_DIR . "/jwk/3_4.rsa_private_key.json");
        $jwk = RSAPrivateKeyJWK::fromJSON($json);
        $this->assertInstanceOf(RSAPrivateKeyJWK::class, $jwk);
    }
}
