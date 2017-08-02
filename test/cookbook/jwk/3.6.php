<?php

use JWX\JWK\Symmetric\SymmetricKeyJWK;

class CookbookSymmetricEncKeyTest extends PHPUnit_Framework_TestCase
{
    public function testJWK()
    {
        $json = file_get_contents(
            COOKBOOK_DIR . "/jwk/3_6.symmetric_key_encryption.json");
        $jwk = SymmetricKeyJWK::fromJSON($json);
        $this->assertInstanceOf(SymmetricKeyJWK::class, $jwk);
    }
}
