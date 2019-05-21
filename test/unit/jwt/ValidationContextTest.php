<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\IssuerClaim;
use Sop\JWX\JWT\Claim\RegisteredClaim;
use Sop\JWX\JWT\Claims;
use Sop\JWX\JWT\Exception\ValidationException;
use Sop\JWX\JWT\ValidationContext;

/**
 * @group jwt
 * @group validator
 *
 * @internal
 */
class ValidationContextTest extends TestCase
{
    public function testCreate()
    {
        $validator = new ValidationContext();
        $this->assertInstanceOf(ValidationContext::class, $validator);
        return $validator;
    }

    /**
     * @depends testCreate
     *
     * @param ValidationContext $ctx
     */
    public function testWithRefTime(ValidationContext $ctx)
    {
        static $ts = 1462774318;
        $ctx = $ctx->withReferenceTime($ts);
        $this->assertEquals($ts, $ctx->referenceTime());
    }

    /**
     * @depends testCreate
     *
     * @param ValidationContext $ctx
     */
    public function testWithoutRefTime(ValidationContext $ctx)
    {
        $ctx = $ctx->withReferenceTime(null);
        $this->assertFalse($ctx->hasReferenceTime());
        return $ctx;
    }

    /**
     * @depends testWithoutRefTime
     *
     * @param ValidationContext $ctx
     */
    public function testRefTimeNotSet(ValidationContext $ctx)
    {
        $this->expectException(\LogicException::class);
        $ctx->referenceTime();
    }

    /**
     * @depends testCreate
     *
     * @param ValidationContext $ctx
     */
    public function testWithLeeway(ValidationContext $ctx)
    {
        static $seconds = 10;
        $ctx = $ctx->withLeeway($seconds);
        $this->assertEquals($seconds, $ctx->leeway());
    }

    /**
     * @depends testCreate
     *
     * @param ValidationContext $ctx
     */
    public function testWithConstraint(ValidationContext $ctx)
    {
        $ctx = $ctx->withConstraint('test', 'value');
        $this->assertEquals('value', $ctx->constraint('test'));
    }

    /**
     * @depends testCreate
     *
     * @param ValidationContext $ctx
     */
    public function testWithIssuer(ValidationContext $ctx)
    {
        static $value = 'issuer';
        $ctx = $ctx->withIssuer($value);
        $this->assertEquals($value,
            $ctx->constraint(RegisteredClaim::NAME_ISSUER));
    }

    /**
     * @depends testCreate
     *
     * @param ValidationContext $ctx
     */
    public function testWithSubject(ValidationContext $ctx)
    {
        static $value = 'subject';
        $ctx = $ctx->withSubject($value);
        $this->assertEquals($value,
            $ctx->constraint(RegisteredClaim::NAME_SUBJECT));
    }

    /**
     * @depends testCreate
     *
     * @param ValidationContext $ctx
     */
    public function testWithAudience(ValidationContext $ctx)
    {
        static $value = 'audience';
        $ctx = $ctx->withAudience($value);
        $this->assertEquals($value,
            $ctx->constraint(RegisteredClaim::NAME_AUDIENCE));
    }

    /**
     * @depends testCreate
     *
     * @param ValidationContext $ctx
     */
    public function testWithID(ValidationContext $ctx)
    {
        static $value = 'id';
        $ctx = $ctx->withID($value);
        $this->assertEquals($value,
            $ctx->constraint(RegisteredClaim::NAME_JWT_ID));
    }

    /**
     * @depends testCreate
     *
     * @param ValidationContext $ctx
     */
    public function testConstaintNotSet(ValidationContext $ctx)
    {
        $this->expectException(\LogicException::class);
        $ctx->constraint('nope');
    }

    /**
     * @depends testCreate
     *
     * @param ValidationContext $ctx
     */
    public function testValidatorNotSet(ValidationContext $ctx)
    {
        $this->expectException(\LogicException::class);
        $ctx->validator('nope');
    }

    /**
     * @depends testCreate
     *
     * @param ValidationContext $ctx
     */
    public function testValidateMissingClaim(ValidationContext $ctx)
    {
        $claims = new Claims();
        $ctx = $ctx->withIssuer('test');
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('is required');
        $ctx->validate($claims);
    }

    /**
     * @depends testCreate
     *
     * @param ValidationContext $ctx
     */
    public function testValidateRequiredFail(ValidationContext $ctx)
    {
        $claims = new Claims(new IssuerClaim('other'));
        $ctx = $ctx->withIssuer('test');
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('failed');
        $ctx->validate($claims);
    }
}
