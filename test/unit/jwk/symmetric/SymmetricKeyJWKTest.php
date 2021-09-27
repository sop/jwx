<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\Util\Base64;

/**
 * @group jwk
 *
 * @internal
 */
class SymmetricKeyJWKTest extends TestCase
{
    public const KEY = 'password';

    public function testCreate()
    {
        $jwk = SymmetricKeyJWK::fromArray(
            ['kty' => 'oct', 'k' => Base64::urlEncode(self::KEY)]);
        $this->assertInstanceOf(SymmetricKeyJWK::class, $jwk);
        return $jwk;
    }

    /**
     * @depends testCreate
     */
    public function testKey(SymmetricKeyJWK $jwk)
    {
        $this->assertEquals(self::KEY, $jwk->key());
    }

    public function testFromKey()
    {
        $jwk = SymmetricKeyJWK::fromKey(self::KEY);
        $this->assertInstanceOf(SymmetricKeyJWK::class, $jwk);
    }

    public function testCreateMissingParameter()
    {
        $this->expectException(\UnexpectedValueException::class);
        new SymmetricKeyJWK();
    }

    public function testInvalidKeyType()
    {
        $this->expectException(\UnexpectedValueException::class);
        SymmetricKeyJWK::fromArray(['kty' => 'nope', 'k' => '']);
    }
}
