<?php

use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\Util\Base64;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 */
class SymmetricKeyJWKTest extends TestCase
{
    const KEY = "password";
    
    public function testCreate()
    {
        $jwk = SymmetricKeyJWK::fromArray(
            array("kty" => "oct", "k" => Base64::urlEncode(self::KEY)));
        $this->assertInstanceOf(SymmetricKeyJWK::class, $jwk);
        return $jwk;
    }
    
    /**
     * @depends testCreate
     *
     * @param SymmetricKeyJWK $jwk
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
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testCreateMissingParameter()
    {
        new SymmetricKeyJWK();
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidKeyType()
    {
        SymmetricKeyJWK::fromArray(array("kty" => "nope", "k" => ""));
    }
}
