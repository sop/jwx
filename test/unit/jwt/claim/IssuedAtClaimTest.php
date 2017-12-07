<?php

use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\IssuedAtClaim;
use JWX\JWT\Claim\RegisteredClaim;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group claim
 */
class IssuedAtClaimTest extends TestCase
{
    const TIME = "Thu, May 12, 2016  2:33:41 PM";
    
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
        $dt = new DateTime(self::TIME, new DateTimeZone("UTC"));
        $this->assertEquals($dt->getTimestamp(), $claim->timestamp());
    }
    
    /**
     * @depends testCreate
     *
     * @param IssuedAtClaim $claim
     */
    public function testDateTime(IssuedAtClaim $claim)
    {
        $dt = new DateTimeImmutable(self::TIME, new DateTimeZone("UTC"));
        $this->assertEquals($dt->getTimestamp(),
            $claim->dateTime()
                ->getTimestamp());
    }
    
    /**
     * @depends testCreate
     * @expectedException RuntimeException
     *
     * @param IssuedAtClaim $claim
     */
    public function testDateTimeFail(IssuedAtClaim $claim)
    {
        $cls = new ReflectionClass($claim);
        $prop = $cls->getProperty("_value");
        $prop->setAccessible(true);
        $prop->setValue($claim, "fail");
        $claim->dateTime();
    }
    
    /**
     * @depends testCreate
     * @expectedException RuntimeException
     *
     * @param IssuedAtClaim $claim
     */
    public function testDateTimeInvalidTimezone(IssuedAtClaim $claim)
    {
        $claim->dateTime("nope");
    }
    
    /**
     * @expectedException RuntimeException
     */
    public function testCreateFail()
    {
        IssuedAtClaim::fromString("nope");
    }
    
    public function testNow()
    {
        $claim = IssuedAtClaim::now();
        $this->assertInstanceOf(IssuedAtClaim::class, $claim);
    }
}
