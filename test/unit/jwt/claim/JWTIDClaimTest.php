<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\Claim;
use Sop\JWX\JWT\Claim\JWTIDClaim;
use Sop\JWX\JWT\Claim\RegisteredClaim;

/**
 * @group jwt
 * @group claim
 *
 * @internal
 */
class JWTIDTest extends TestCase
{
    public const VALUE = 'uuid';

    public function testCreate()
    {
        $claim = new JWTIDClaim(self::VALUE);
        $this->assertInstanceOf(JWTIDClaim::class, $claim);
        return $claim;
    }

    /**
     * @depends testCreate
     */
    public function testClaimName(Claim $claim)
    {
        $this->assertEquals(RegisteredClaim::NAME_JWT_ID, $claim->name());
    }

    /**
     * @dataProvider validateProvider
     *
     * @param mixed $constraint
     * @param mixed $result
     */
    public function testValidate($constraint, $result)
    {
        $claim = JWTIDClaim::fromJSONValue(self::VALUE);
        $this->assertEquals($result, $claim->validate($constraint));
    }

    public function validateProvider()
    {
        return [
            [self::VALUE, true],
            ['nope', false],
        ];
    }
}
