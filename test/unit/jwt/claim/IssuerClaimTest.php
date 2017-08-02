<?php

use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\IssuerClaim;
use JWX\JWT\Claim\RegisteredClaim;

/**
 * @group jwt
 * @group claim
 */
class IssuerClaimTest extends PHPUnit_Framework_TestCase
{
    const VALUE = "issuer";
    
    public function testCreate()
    {
        $claim = new IssuerClaim(self::VALUE);
        $this->assertInstanceOf(IssuerClaim::class, $claim);
        return $claim;
    }
    
    /**
     * @depends testCreate
     *
     * @param Claim $claim
     */
    public function testClaimName(Claim $claim)
    {
        $this->assertEquals(RegisteredClaim::NAME_ISSUER, $claim->name());
    }
    
    /**
     * @dataProvider validateProvider
     */
    public function testValidate($constraint, $result)
    {
        $claim = IssuerClaim::fromJSONValue(self::VALUE);
        $this->assertEquals($result, $claim->validate($constraint));
    }
    
    public function validateProvider()
    {
        return array(
            /* @formatter:off */
            [self::VALUE, true],
            ["nope", false]
            /* @formatter:on */
        );
    }
}
