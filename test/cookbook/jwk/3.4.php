<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\RSA\RSAPrivateKeyJWK;

/**
 * @internal
 */
class CookbookRSAPrivateKeyTest extends TestCase
{
    public function testJWK()
    {
        $json = file_get_contents(COOKBOOK_DIR . '/jwk/3_4.rsa_private_key.json');
        $jwk = RSAPrivateKeyJWK::fromJSON($json);
        $this->assertInstanceOf(RSAPrivateKeyJWK::class, $jwk);
    }
}
