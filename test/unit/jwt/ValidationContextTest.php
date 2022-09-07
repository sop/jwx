<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
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
     */
    public function testWithRefTime(ValidationContext $ctx)
    {
        static $ts = 1462774318;
        $ctx = $ctx->withReferenceTime($ts);
        $this->assertEquals($ts, $ctx->referenceTime());
    }

    /**
     * @depends testCreate
     */
    public function testWithoutRefTime(ValidationContext $ctx)
    {
        $ctx = $ctx->withReferenceTime(null);
        $this->assertFalse($ctx->hasReferenceTime());
        return $ctx;
    }

    /**
     * @depends testWithoutRefTime
     */
    public function testRefTimeNotSet(ValidationContext $ctx)
    {
        $this->expectException(\LogicException::class);
        $ctx->referenceTime();
    }

    /**
     * @depends testCreate
     */
    public function testWithLeeway(ValidationContext $ctx)
    {
        static $seconds = 10;
        $ctx = $ctx->withLeeway($seconds);
        $this->assertEquals($seconds, $ctx->leeway());
    }

    /**
     * @depends testCreate
     */
    public function testWithConstraint(ValidationContext $ctx)
    {
        $ctx = $ctx->withConstraint('test', 'value');
        $this->assertEquals('value', $ctx->constraint('test'));
    }

    /**
     * @depends testCreate
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
     */
    public function testConstaintNotSet(ValidationContext $ctx)
    {
        $this->expectException(\LogicException::class);
        $ctx->constraint('nope');
    }

    /**
     * @depends testCreate
     */
    public function testValidatorNotSet(ValidationContext $ctx)
    {
        $this->expectException(\LogicException::class);
        $ctx->validator('nope');
    }

    /**
     * @depends testCreate
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
     */
    public function testValidateRequiredFail(ValidationContext $ctx)
    {
        $claims = new Claims(new IssuerClaim('other'));
        $ctx = $ctx->withIssuer('test');
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('failed');
        $ctx->validate($claims);
    }

    /**
     * @depends testCreate
     */
    public function testAddPermittedAlgorithm(ValidationContext $ctx)
    {
        $this->assertTrue($ctx->isPermittedAlgorithm(JWA::ALGO_RS256));
        $this->assertFalse($ctx->isPermittedAlgorithm('test'));
        $ctx = $ctx->withPermittedAlgorithmsAdded('test');
        $this->assertTrue($ctx->isPermittedAlgorithm(JWA::ALGO_RS256));
        $this->assertTrue($ctx->isPermittedAlgorithm('test'));
    }

    /**
     * @depends testCreate
     */
    public function testNewPermittedAlgorithm(ValidationContext $ctx)
    {
        $this->assertTrue($ctx->isPermittedAlgorithm(JWA::ALGO_RS256));
        $ctx = $ctx->withPermittedAlgorithms('test');
        $this->assertFalse($ctx->isPermittedAlgorithm(JWA::ALGO_RS256));
        $this->assertTrue($ctx->isPermittedAlgorithm('test'));
    }

    /**
     * @depends testCreate
     */
    public function testProhibitedAlgorithm(ValidationContext $ctx)
    {
        $this->assertTrue($ctx->isPermittedAlgorithm(JWA::ALGO_RS256));
        $ctx = $ctx->withProhibitedAlgorithms(JWA::ALGO_RS256);
        $this->assertFalse($ctx->isPermittedAlgorithm(JWA::ALGO_RS256));
    }
}
