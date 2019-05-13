<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;

/**
 * @internal
 */
class CookbookSymmetricEncKeyTest extends TestCase
{
    public function testJWK()
    {
        $json = file_get_contents(COOKBOOK_DIR . '/jwk/3_6.symmetric_key_encryption.json');
        $jwk = SymmetricKeyJWK::fromJSON($json);
        $this->assertInstanceOf(SymmetricKeyJWK::class, $jwk);
    }
}
