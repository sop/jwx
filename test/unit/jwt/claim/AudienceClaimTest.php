<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\AudienceClaim;
use Sop\JWX\JWT\Claim\Claim;
use Sop\JWX\JWT\Claim\RegisteredClaim;

/**
 * @group jwt
 * @group claim
 *
 * @internal
 */
class AudienceClaimTest extends TestCase
{
    public const VALUE_SINGLE = 'audience';

    public const VALUE_MANY = ['audience #1', 'audience #2'];

    public function testCreate()
    {
        $claim = new AudienceClaim(self::VALUE_SINGLE);
        $this->assertInstanceOf(AudienceClaim::class, $claim);
        return $claim;
    }

    /**
     * @depends testCreate
     */
    public function testClaimName(Claim $claim)
    {
        $this->assertEquals(RegisteredClaim::NAME_AUDIENCE, $claim->name());
    }

    /**
     * @dataProvider validateProvider
     *
     * @param mixed $value
     * @param mixed $constraint
     * @param mixed $result
     */
    public function testValidate($value, $constraint, $result)
    {
        $claim = AudienceClaim::fromJSONValue($value);
        $this->assertEquals($result, $claim->validate($constraint));
    }

    public function validateProvider()
    {
        return [
            [self::VALUE_SINGLE, self::VALUE_SINGLE, true],
            [self::VALUE_SINGLE, 'nope', false],
            [self::VALUE_MANY, self::VALUE_MANY[1], true],
            [self::VALUE_MANY, 'nope', false],
        ];
    }
}
