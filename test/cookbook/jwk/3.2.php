<?php

use JWX\JWK\EC\ECPrivateKeyJWK;

class CookbookECPrivateKeyTest extends PHPUnit_Framework_TestCase
{
    public function testJWK()
    {
        $json = file_get_contents(COOKBOOK_DIR . "/jwk/3_2.ec_private_key.json");
        $jwk = ECPrivateKeyJWK::fromJSON($json);
        $this->assertInstanceOf(ECPrivateKeyJWK::class, $jwk);
    }
}
