<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\Claim;
use Sop\JWX\JWT\Claim\ExpirationTimeClaim;
use Sop\JWX\JWT\Claim\RegisteredClaim;
use Sop\JWX\JWT\ValidationContext;

/**
 * @group jwt
 * @group claim
 *
 * @internal
 */
class ExpirationTimeClaimTest extends TestCase
{
    public const VALUE = 1460703960;

    public function testCreate()
    {
        $claim = new ExpirationTimeClaim(self::VALUE);
        $this->assertInstanceOf(ExpirationTimeClaim::class, $claim);
        return $claim;
    }

    /**
     * @depends testCreate
     */
    public function testClaimName(Claim $claim)
    {
        $this->assertEquals(RegisteredClaim::NAME_EXPIRATION_TIME,
            $claim->name());
    }

    /**
     * @dataProvider validateProvider
     *
     * @param mixed $constraint
     * @param mixed $result
     */
    public function testValidate($constraint, $result)
    {
        $claim = ExpirationTimeClaim::fromJSONValue(self::VALUE);
        $this->assertEquals($result, $claim->validate($constraint));
    }

    public function validateProvider()
    {
        return [
            [self::VALUE - 1, true],
            [self::VALUE, false],
            [self::VALUE + 1, false],
        ];
    }

    /**
     * @dataProvider provideValidateWithContext
     *
     * @param null|int $reftime
     * @param int      $leeway
     * @param bool     $result
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
        return [
            [self::VALUE, 0, false],
            [self::VALUE - 1, 0, true],
            [self::VALUE, 1, true],
            [self::VALUE + 1, 1, false],
            [self::VALUE + 1, 2, true],
            [null, 0, true],
        ];
    }
}
