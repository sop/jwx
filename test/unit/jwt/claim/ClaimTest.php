<?php

use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\Validator\EqualsValidator;
use JWX\JWT\ValidationContext;


/**
 * @group jwt
 * @group claim
 */
class ClaimTest extends PHPUnit_Framework_TestCase
{
	public function testCustomClaimWithoutValidatorValidate() {
		$claim = new Claim("test", "value");
		$this->assertTrue($claim->validate("nope"));
	}
	
	public function testCustomClaimValidate() {
		$claim = new Claim("test", "value", new EqualsValidator());
		$this->assertTrue($claim->validate("value"));
		$this->assertFalse($claim->validate("nope"));
	}
	
	public function testCustomClaimFromNameAndValue() {
		$claim = Claim::fromNameAndValue("test", "value");
		$this->assertInstanceOf(Claim::class, $claim);
	}
	
	public function testValidateWithContext() {
		$claim = new Claim("test", "value");
		$ctx = new ValidationContext(["test" => "value"]);
		$this->assertTrue($claim->validateWithContext($ctx));
	}
	
	public function testValidateWithContextNoConstraint() {
		$claim = new Claim("test", "value");
		$ctx = new ValidationContext();
		$this->assertTrue($claim->validateWithContext($ctx));
	}
}
