<?php

use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\RegisteredClaim;
use JWX\JWT\Claim\SubjectClaim;

/**
 * @group jwt
 * @group claim
 */
class SubjectClaimTest extends PHPUnit_Framework_TestCase
{
    const VALUE = "subject";
    
    public function testCreate()
    {
        $claim = new SubjectClaim(self::VALUE);
        $this->assertInstanceOf(SubjectClaim::class, $claim);
        return $claim;
    }
    
    /**
     * @depends testCreate
     *
     * @param Claim $claim
     */
    public function testClaimName(Claim $claim)
    {
        $this->assertEquals(RegisteredClaim::NAME_SUBJECT, $claim->name());
    }
    
    /**
     * @dataProvider validateProvider
     */
    public function testValidate($constraint, $result)
    {
        $claim = SubjectClaim::fromJSONValue(self::VALUE);
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
