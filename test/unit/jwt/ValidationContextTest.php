<?php

use JWX\JWT\ValidationContext;
use JWX\JWT\Claim\RegisteredClaim;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group validator
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
     * @expectedException LogicException
     *
     * @param ValidationContext $ctx
     */
    public function testRefTimeNotSet(ValidationContext $ctx)
    {
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
        $ctx = $ctx->withConstraint("test", "value");
        $this->assertEquals("value", $ctx->constraint("test"));
    }
    
    /**
     * @depends testCreate
     *
     * @param ValidationContext $ctx
     */
    public function testWithIssuer(ValidationContext $ctx)
    {
        static $value = "issuer";
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
        static $value = "subject";
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
        static $value = "audience";
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
        static $value = "id";
        $ctx = $ctx->withID($value);
        $this->assertEquals($value,
            $ctx->constraint(RegisteredClaim::NAME_JWT_ID));
    }
    
    /**
     * @depends testCreate
     * @expectedException LogicException
     *
     * @param ValidationContext $ctx
     */
    public function testConstaintNotSet(ValidationContext $ctx)
    {
        $ctx->constraint("nope");
    }
    
    /**
     * @depends testCreate
     * @expectedException LogicException
     *
     * @param ValidationContext $ctx
     */
    public function testValidatorNotSet(ValidationContext $ctx)
    {
        $ctx->validator("nope");
    }
}
