<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\AudienceClaim;
use Sop\JWX\JWT\Claim\Claim;
use Sop\JWX\JWT\Claim\ExpirationTimeClaim;
use Sop\JWX\JWT\Claim\IssuedAtClaim;
use Sop\JWX\JWT\Claim\IssuerClaim;
use Sop\JWX\JWT\Claim\JWTIDClaim;
use Sop\JWX\JWT\Claim\NotBeforeClaim;
use Sop\JWX\JWT\Claim\SubjectClaim;
use Sop\JWX\JWT\Claim\Validator\LessValidator;
use Sop\JWX\JWT\Claims;
use Sop\JWX\JWT\Exception\ValidationException;
use Sop\JWX\JWT\ValidationContext;

/**
 * @group jwt
 * @group claim
 *
 * @internal
 */
class ClaimsValidateTest extends TestCase
{
    const REF_TIME = 1460293103;

    private static $_claims;

    public function setUp(): void
    {
        self::$_claims = new Claims(new IssuerClaim('issuer'),
            new SubjectClaim('subject'), new AudienceClaim('test'),
            new ExpirationTimeClaim(self::REF_TIME + 60),
            new NotBeforeClaim(self::REF_TIME), new IssuedAtClaim(self::REF_TIME),
            new JWTIDClaim('id'));
    }

    public function tearDown(): void
    {
        self::$_claims = null;
    }

    public function testValidateTime()
    {
        $ctx = new ValidationContext();
        $ctx = $ctx->withReferenceTime(self::REF_TIME);
        $this->assertInstanceOf(ValidationContext::class,
            $ctx->validate(self::$_claims));
    }

    public function testValidateLeeway()
    {
        $ctx = (new ValidationContext())->withLeeway(10);
        $ctx = $ctx->withReferenceTime(self::REF_TIME + 69);
        $this->assertInstanceOf(ValidationContext::class,
            $ctx->validate(self::$_claims));
    }

    public function testValidateLeewayFails()
    {
        $ctx = (new ValidationContext())->withLeeway(10);
        $ctx = $ctx->withReferenceTime(self::REF_TIME + 70);
        $this->expectException(ValidationException::class);
        $ctx->validate(self::$_claims);
    }

    public function testValidateExpired()
    {
        $ctx = (new ValidationContext())->withLeeway(0);
        $ctx = $ctx->withReferenceTime(self::REF_TIME + 60);
        $this->expectException(ValidationException::class);
        $ctx->validate(self::$_claims);
    }

    public function testValidateNotBeforeFails()
    {
        $ctx = (new ValidationContext())->withLeeway(0);
        $ctx = $ctx->withReferenceTime(self::REF_TIME - 1);
        $this->expectException(ValidationException::class);
        $ctx->validate(self::$_claims);
    }

    public function testValidateIssuer()
    {
        $ctx = new ValidationContext();
        $ctx = $ctx->withReferenceTime(null)->withIssuer('issuer');
        $this->assertInstanceOf(ValidationContext::class,
            $ctx->validate(self::$_claims));
    }

    public function testValidateIssuerFails()
    {
        $ctx = new ValidationContext();
        $ctx = $ctx->withReferenceTime(null)->withIssuer('nope');
        $this->expectException(ValidationException::class);
        $ctx->validate(self::$_claims);
    }

    public function testValidateSubject()
    {
        $ctx = new ValidationContext();
        $ctx = $ctx->withReferenceTime(null)->withSubject('subject');
        $this->assertInstanceOf(ValidationContext::class,
            $ctx->validate(self::$_claims));
    }

    public function testValidateSubjectFails()
    {
        $ctx = new ValidationContext();
        $ctx = $ctx->withReferenceTime(null)->withSubject('nope');
        $this->expectException(ValidationException::class);
        $ctx->validate(self::$_claims);
    }

    public function testValidateAudience()
    {
        $ctx = new ValidationContext();
        $ctx = $ctx->withReferenceTime(null)->withAudience('test');
        $this->assertInstanceOf(ValidationContext::class,
            $ctx->validate(self::$_claims));
    }

    public function testValidateAudienceFails()
    {
        $ctx = new ValidationContext();
        $ctx = $ctx->withReferenceTime(null)->withAudience('nope');
        $this->expectException(ValidationException::class);
        $ctx->validate(self::$_claims);
    }

    public function testValidateID()
    {
        $ctx = new ValidationContext();
        $ctx = $ctx->withReferenceTime(null)->withID('id');
        $this->assertInstanceOf(ValidationContext::class,
            $ctx->validate(self::$_claims));
    }

    public function testValidateIDFails()
    {
        $ctx = new ValidationContext();
        $ctx = $ctx->withReferenceTime(null)->withID('nope');
        $this->expectException(ValidationException::class);
        $ctx->validate(self::$_claims);
    }

    public function testCustomClaim()
    {
        $claims = new Claims(new Claim('test', 0, new LessValidator()));
        $ctx = new ValidationContext(['test' => 1]);
        $this->assertInstanceOf(ValidationContext::class,
            $ctx->validate($claims));
    }

    public function testCustomClaimFails()
    {
        $claims = new Claims(new Claim('test', 0, new LessValidator()));
        $ctx = new ValidationContext(['test' => 0]);
        $this->expectException(ValidationException::class);
        $ctx->validate($claims);
    }

    public function testClaimsIsValid()
    {
        $ctx = new ValidationContext();
        $ctx = $ctx->withReferenceTime(self::REF_TIME);
        $this->assertTrue(self::$_claims->isValid($ctx));
    }

    public function testClaimsIsNotValid()
    {
        $ctx = new ValidationContext();
        $ctx = $ctx->withReferenceTime(self::REF_TIME)->withIssuer('nope');
        $this->assertFalse(self::$_claims->isValid($ctx));
    }
}
