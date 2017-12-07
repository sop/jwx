<?php

use JWX\JWK\RSA\RSAPublicKeyJWK;
use PHPUnit\Framework\TestCase;

class CookbookRSAPublicKeyTest extends TestCase
{
    public function testJWK()
    {
        $json = file_get_contents(COOKBOOK_DIR . "/jwk/3_3.rsa_public_key.json");
        $jwk = RSAPublicKeyJWK::fromJSON($json);
        $this->assertInstanceOf(RSAPublicKeyJWK::class, $jwk);
    }
}
