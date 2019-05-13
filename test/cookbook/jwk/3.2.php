<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\EC\ECPrivateKeyJWK;

/**
 * @internal
 */
class CookbookECPrivateKeyTest extends TestCase
{
    public function testJWK()
    {
        $json = file_get_contents(COOKBOOK_DIR . '/jwk/3_2.ec_private_key.json');
        $jwk = ECPrivateKeyJWK::fromJSON($json);
        $this->assertInstanceOf(ECPrivateKeyJWK::class, $jwk);
    }
}
