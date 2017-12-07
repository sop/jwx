<?php

use JWX\JWK\EC\ECPublicKeyJWK;
use PHPUnit\Framework\TestCase;

class CookbookECPublicKeyTest extends TestCase
{
    public function testJWK()
    {
        $json = file_get_contents(COOKBOOK_DIR . "/jwk/3_1.ec_public_key.json");
        $jwk = ECPublicKeyJWK::fromJSON($json);
        $this->assertInstanceOf(ECPublicKeyJWK::class, $jwk);
    }
}
