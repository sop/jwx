<?php

use JWX\JWK\Symmetric\SymmetricKeyJWK;

class CookbookSymmetricMacKeyTest extends PHPUnit_Framework_TestCase
{
    public function testJWK()
    {
        $json = file_get_contents(
            COOKBOOK_DIR . "/jwk/3_5.symmetric_key_mac_computation.json");
        $jwk = SymmetricKeyJWK::fromJSON($json);
        $this->assertInstanceOf(SymmetricKeyJWK::class, $jwk);
    }
}
