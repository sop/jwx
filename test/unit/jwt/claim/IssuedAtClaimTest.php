<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\Claim;
use Sop\JWX\JWT\Claim\IssuedAtClaim;
use Sop\JWX\JWT\Claim\RegisteredClaim;

/**
 * @group jwt
 * @group claim
 *
 * @internal
 */
class IssuedAtClaimTest extends TestCase
{
    const TIME = 'Thu, May 12, 2016  2:33:41 PM';

    public function testCreate()
    {
        $claim = IssuedAtClaim::fromString(self::TIME);
        $this->assertInstanceOf(IssuedAtClaim::class, $claim);
        return $claim;
    }

    /**
     * @depends testCreate
     *
     * @param Claim $claim
     */
    public function testClaimName(Claim $claim)
    {
        $this->assertEquals(RegisteredClaim::NAME_ISSUED_AT, $claim->name());
    }

    /**
     * @depends testCreate
     *
     * @param IssuedAtClaim $claim
     */
    public function testTimestamp(IssuedAtClaim $claim)
    {
        $dt = new DateTime(self::TIME, new DateTimeZone('UTC'));
        $this->assertEquals($dt->getTimestamp(), $claim->timestamp());
    }

    /**
     * @depends testCreate
     *
     * @param IssuedAtClaim $claim
     */
    public function testDateTime(IssuedAtClaim $claim)
    {
        $dt = new DateTimeImmutable(self::TIME, new DateTimeZone('UTC'));
        $this->assertEquals($dt->getTimestamp(),
            $claim->dateTime()->getTimestamp());
    }

    /**
     * @depends testCreate
     *
     * @param IssuedAtClaim $claim
     */
    public function testDateTimeFail(IssuedAtClaim $claim)
    {
        $cls = new ReflectionClass($claim);
        $prop = $cls->getProperty('_value');
        $prop->setAccessible(true);
        $prop->setValue($claim, 'fail');
        $this->expectException(\RuntimeException::class);
        $claim->dateTime();
    }

    /**
     * @depends testCreate
     *
     * @param IssuedAtClaim $claim
     */
    public function testDateTimeInvalidTimezone(IssuedAtClaim $claim)
    {
        $this->expectException(\RuntimeException::class);
        $claim->dateTime('nope');
    }

    public function testCreateFail()
    {
        $this->expectException(\RuntimeException::class);
        IssuedAtClaim::fromString('nope');
    }

    public function testNow()
    {
        $claim = IssuedAtClaim::now();
        $this->assertInstanceOf(IssuedAtClaim::class, $claim);
    }
}
