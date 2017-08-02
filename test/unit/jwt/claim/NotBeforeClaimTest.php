<?php

use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\NotBeforeClaim;
use JWX\JWT\Claim\RegisteredClaim;

/**
 * @group jwt
 * @group claim
 */
class NotBeforeClaimTest extends PHPUnit_Framework_TestCase
{
    const VALUE = 1460703960;
    
    public function testCreate()
    {
        $claim = new NotBeforeClaim(self::VALUE);
        $this->assertInstanceOf(NotBeforeClaim::class, $claim);
        return $claim;
    }
    
    /**
     * @depends testCreate
     *
     * @param Claim $claim
     */
    public function testClaimName(Claim $claim)
    {
        $this->assertEquals(RegisteredClaim::NAME_NOT_BEFORE, $claim->name());
    }
    
    /**
     * @dataProvider validateProvider
     */
    public function testValidate($constraint, $result)
    {
        $claim = NotBeforeClaim::fromJSONValue(self::VALUE);
        $this->assertEquals($result, $claim->validate($constraint));
    }
    
    public function validateProvider()
    {
        return array(
            /* @formatter:off */
            [self::VALUE, true],
            [self::VALUE + 1, true],
            [self::VALUE - 1, false]
            /* @formatter:on */
        );
    }
    
    public function testNow()
    {
        $claim = NotBeforeClaim::now();
        $this->assertInstanceOf(NotBeforeClaim::class, $claim);
    }
}
