<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\Claim;
use Sop\JWX\JWT\Claim\Validator\EqualsValidator;
use Sop\JWX\JWT\ValidationContext;

/**
 * @group jwt
 * @group claim
 *
 * @internal
 */
class ClaimTest extends TestCase
{
    public function testCustomClaimWithoutValidatorValidate()
    {
        $claim = new Claim('test', 'value');
        $this->assertFalse($claim->validate('nope'));
    }

    public function testCustomClaimValidate()
    {
        $claim = new Claim('test', 'value', new EqualsValidator());
        $this->assertTrue($claim->validate('value'));
        $this->assertFalse($claim->validate('nope'));
    }

    public function testCustomClaimFromNameAndValue()
    {
        $claim = Claim::fromNameAndValue('test', 'value');
        $this->assertInstanceOf(Claim::class, $claim);
    }

    public function testValidateWithContext()
    {
        $claim = new Claim('test', 'value');
        $ctx = new ValidationContext();
        $ctx = $ctx->withConstraint('test', 'value', new EqualsValidator());
        $this->assertTrue($claim->validateWithContext($ctx));
    }

    public function testValidateWithContextFails()
    {
        $claim = new Claim('test', 'value');
        $ctx = new ValidationContext();
        $ctx = $ctx->withConstraint('test', 'fail', new EqualsValidator());
        $this->assertFalse($claim->validateWithContext($ctx));
    }

    public function testValidateWithContextNoValidator()
    {
        $claim = new Claim('test', 'value');
        $ctx = new ValidationContext(['test' => 'value']);
        $this->assertFalse($claim->validateWithContext($ctx));
    }

    public function testValidateWithContextNoConstraint()
    {
        $claim = new Claim('test', 'value');
        $ctx = new ValidationContext();
        $this->assertTrue($claim->validateWithContext($ctx));
    }
}
