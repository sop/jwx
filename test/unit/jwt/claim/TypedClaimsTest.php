<?php

use JWX\JWT\Claims;
use JWX\JWT\Claim\AudienceClaim;
use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\ExpirationTimeClaim;
use JWX\JWT\Claim\IssuedAtClaim;
use JWX\JWT\Claim\IssuerClaim;
use JWX\JWT\Claim\JWTIDClaim;
use JWX\JWT\Claim\NotBeforeClaim;
use JWX\JWT\Claim\SubjectClaim;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group claim
 */
class TypedClaimsTest extends TestCase
{
    private static $_claims;
    
    public static function setUpBeforeClass()
    {
        self::$_claims = new Claims(new IssuerClaim("issuer"),
            new SubjectClaim("subject"), new AudienceClaim("audience 1"),
            ExpirationTimeClaim::fromString("now + 1 hour"),
            NotBeforeClaim::now(), IssuedAtClaim::now(), new JWTIDClaim("id"));
    }
    
    public static function tearDownAfterClass()
    {
        self::$_claims = null;
    }
    
    public function testHasIssuer()
    {
        $this->assertTrue(self::$_claims->hasIssuer());
    }
    
    public function testIssuer()
    {
        $this->assertInstanceOf(IssuerClaim::class, self::$_claims->issuer());
    }
    
    public function testHasSubject()
    {
        $this->assertTrue(self::$_claims->hasSubject());
    }
    
    public function testSubject()
    {
        $this->assertInstanceOf(SubjectClaim::class, self::$_claims->subject());
    }
    
    public function testHasAudience()
    {
        $this->assertTrue(self::$_claims->hasAudience());
    }
    
    public function testAudience()
    {
        $this->assertInstanceOf(AudienceClaim::class, self::$_claims->audience());
    }
    
    public function testHasExpirationTime()
    {
        $this->assertTrue(self::$_claims->hasExpirationTime());
    }
    
    public function testExpirationTime()
    {
        $this->assertInstanceOf(ExpirationTimeClaim::class,
            self::$_claims->expirationTime());
    }
    
    public function testHasNotBefore()
    {
        $this->assertTrue(self::$_claims->hasNotBefore());
    }
    
    public function testNotBefore()
    {
        $this->assertInstanceOf(NotBeforeClaim::class,
            self::$_claims->notBefore());
    }
    
    public function testHasIssuedAt()
    {
        $this->assertTrue(self::$_claims->hasIssuedAt());
    }
    
    public function testIssuedAt()
    {
        $this->assertInstanceOf(IssuedAtClaim::class, self::$_claims->issuedAt());
    }
    
    public function testHasJWTID()
    {
        $this->assertTrue(self::$_claims->hasJWTID());
    }
    
    public function testJWTID()
    {
        $this->assertInstanceOf(JWTIDClaim::class, self::$_claims->JWTID());
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testCheckTypeFails()
    {
        $claims = new Claims(new Claim("iss", "fail"));
        $claims->issuer();
    }
}
