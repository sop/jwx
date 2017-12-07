<?php

use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\JWTIDClaim;
use JWX\JWT\Claim\RegisteredClaim;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group claim
 */
class JWTIDTest extends TestCase
{
    const VALUE = "uuid";
    
    public function testCreate()
    {
        $claim = new JWTIDClaim(self::VALUE);
        $this->assertInstanceOf(JWTIDClaim::class, $claim);
        return $claim;
    }
    
    /**
     * @depends testCreate
     *
     * @param Claim $claim
     */
    public function testClaimName(Claim $claim)
    {
        $this->assertEquals(RegisteredClaim::NAME_JWT_ID, $claim->name());
    }
    
    /**
     * @dataProvider validateProvider
     */
    public function testValidate($constraint, $result)
    {
        $claim = JWTIDClaim::fromJSONValue(self::VALUE);
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
