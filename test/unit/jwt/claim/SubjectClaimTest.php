<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\Claim;
use Sop\JWX\JWT\Claim\RegisteredClaim;
use Sop\JWX\JWT\Claim\SubjectClaim;

/**
 * @group jwt
 * @group claim
 *
 * @internal
 */
class SubjectClaimTest extends TestCase
{
    const VALUE = 'subject';

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
     *
     * @param mixed $constraint
     * @param mixed $result
     */
    public function testValidate($constraint, $result)
    {
        $claim = SubjectClaim::fromJSONValue(self::VALUE);
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
