<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\Claim;
use Sop\JWX\JWT\Claim\IssuerClaim;
use Sop\JWX\JWT\Claim\RegisteredClaim;

/**
 * @group jwt
 * @group claim
 *
 * @internal
 */
class IssuerClaimTest extends TestCase
{
    const VALUE = 'issuer';

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
     *
     * @param mixed $constraint
     * @param mixed $result
     */
    public function testValidate($constraint, $result)
    {
        $claim = IssuerClaim::fromJSONValue(self::VALUE);
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
