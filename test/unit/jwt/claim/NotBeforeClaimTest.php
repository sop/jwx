<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\Claim;
use Sop\JWX\JWT\Claim\NotBeforeClaim;
use Sop\JWX\JWT\Claim\RegisteredClaim;

/**
 * @group jwt
 * @group claim
 *
 * @internal
 */
class NotBeforeClaimTest extends TestCase
{
    public const VALUE = 1460703960;

    public function testCreate()
    {
        $claim = new NotBeforeClaim(self::VALUE);
        $this->assertInstanceOf(NotBeforeClaim::class, $claim);
        return $claim;
    }

    /**
     * @depends testCreate
     */
    public function testClaimName(Claim $claim)
    {
        $this->assertEquals(RegisteredClaim::NAME_NOT_BEFORE, $claim->name());
    }

    /**
     * @dataProvider validateProvider
     *
     * @param mixed $constraint
     * @param mixed $result
     */
    public function testValidate($constraint, $result)
    {
        $claim = NotBeforeClaim::fromJSONValue(self::VALUE);
        $this->assertEquals($result, $claim->validate($constraint));
    }

    public function validateProvider()
    {
        return [
            [self::VALUE, true],
            [self::VALUE + 1, true],
            [self::VALUE - 1, false],
        ];
    }

    public function testNow()
    {
        $claim = NotBeforeClaim::now();
        $this->assertInstanceOf(NotBeforeClaim::class, $claim);
    }
}
