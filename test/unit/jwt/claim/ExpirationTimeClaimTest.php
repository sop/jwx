<?php

use JWX\JWT\ValidationContext;
use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\ExpirationTimeClaim;
use JWX\JWT\Claim\RegisteredClaim;

/**
 * @group jwt
 * @group claim
 */
class ExpirationTimeClaimTest extends PHPUnit_Framework_TestCase
{
    const VALUE = 1460703960;
    
    public function testCreate()
    {
        $claim = new ExpirationTimeClaim(self::VALUE);
        $this->assertInstanceOf(ExpirationTimeClaim::class, $claim);
        return $claim;
    }
    
    /**
     * @depends testCreate
     *
     * @param Claim $claim
     */
    public function testClaimName(Claim $claim)
    {
        $this->assertEquals(RegisteredClaim::NAME_EXPIRATION_TIME,
            $claim->name());
    }
    
    /**
     * @dataProvider validateProvider
     */
    public function testValidate($constraint, $result)
    {
        $claim = ExpirationTimeClaim::fromJSONValue(self::VALUE);
        $this->assertEquals($result, $claim->validate($constraint));
    }
    
    public function validateProvider()
    {
        return array(
            /* @formatter:off */
            [self::VALUE - 1, true],
            [self::VALUE, false],
            [self::VALUE + 1, false]
            /* @formatter:on */
        );
    }
    
    /**
     * @dataProvider provideValidateWithContext
     *
     * @param int|null $reftime
     * @param int $leeway
     * @param bool $result
     */
    public function testValidateWithContext($reftime, $leeway, $result)
    {
        $ctx = new ValidationContext();
        $ctx = $ctx->withReferenceTime($reftime)->withLeeway($leeway);
        $claim = ExpirationTimeClaim::fromJSONValue(self::VALUE);
        $this->assertEquals($result, $claim->validateWithContext($ctx));
    }
    
    public function provideValidateWithContext()
    {
        return array(
            /* @formatter:off */
            [self::VALUE, 0, false],
            [self::VALUE - 1, 0, true],
            [self::VALUE, 1, true],
            [self::VALUE + 1, 1, false],
            [self::VALUE + 1, 2, true],
            [null, 0, true]
            /* @formatter:on */
        );
    }
}
