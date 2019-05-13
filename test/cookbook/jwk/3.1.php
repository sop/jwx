<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\EC\ECPublicKeyJWK;

/**
 * @internal
 */
class CookbookECPublicKeyTest extends TestCase
{
    public function testJWK()
    {
        $json = file_get_contents(COOKBOOK_DIR . '/jwk/3_1.ec_public_key.json');
        $jwk = ECPublicKeyJWK::fromJSON($json);
        $this->assertInstanceOf(ECPublicKeyJWK::class, $jwk);
    }
}
