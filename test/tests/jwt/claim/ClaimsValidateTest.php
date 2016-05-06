<?php

use JWX\JWT\Claims;
use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\IssuerClaim;
use JWX\JWT\Claim\SubjectClaim;
use JWX\JWT\Claim\AudienceClaim;
use JWX\JWT\Claim\ExpirationTimeClaim;
use JWX\JWT\Claim\NotBeforeClaim;
use JWX\JWT\Claim\IssuedAtClaim;
use JWX\JWT\Claim\JWTIDClaim;
use JWX\JWT\Claim\Validator\LessValidator;
use JWX\JWT\ValidationContext;


/**
 * @group claim
 */
class ClaimsValidateTest extends PHPUnit_Framework_TestCase
{
	const REF_TIME = 1460293103;
	
	private $_claims;
	
	public function setUp() {
		$this->_claims = new Claims(new IssuerClaim("issuer"), 
			new SubjectClaim("subject"), new AudienceClaim("test"), 
			new ExpirationTimeClaim(self::REF_TIME + 60), 
			new NotBeforeClaim(self::REF_TIME), 
			new IssuedAtClaim(self::REF_TIME), new JWTIDClaim("id"));
	}
	
	public function tearDown() {
		$this->_claims = null;
	}
	
	public function testValidateTime() {
		$ctx = new ValidationContext();
		$ctx = $ctx->withReferenceTime(self::REF_TIME);
		$this->assertInstanceOf(ValidationContext::class, 
			$ctx->validate($this->_claims));
	}
	
	public function testValidateLeeway() {
		$ctx = (new ValidationContext())->withLeeway(10);
		$ctx = $ctx->withReferenceTime(self::REF_TIME + 69);
		$this->assertInstanceOf(ValidationContext::class, 
			$ctx->validate($this->_claims));
	}
	
	/**
	 * @expectedException JWX\JWT\Exception\ValidationException
	 */
	public function testValidateLeewayFails() {
		$ctx = (new ValidationContext())->withLeeway(10);
		$ctx = $ctx->withReferenceTime(self::REF_TIME + 70);
		$ctx->validate($this->_claims);
	}
	
	/**
	 * @expectedException JWX\JWT\Exception\ValidationException
	 */
	public function testValidateExpired() {
		$ctx = (new ValidationContext())->withLeeway(0);
		$ctx = $ctx->withReferenceTime(self::REF_TIME + 60);
		$ctx->validate($this->_claims);
	}
	
	/**
	 * @expectedException JWX\JWT\Exception\ValidationException
	 */
	public function testValidateNotBeforeFails() {
		$ctx = (new ValidationContext())->withLeeway(0);
		$ctx = $ctx->withReferenceTime(self::REF_TIME - 1);
		$ctx->validate($this->_claims);
	}
	
	public function testValidateIssuer() {
		$ctx = new ValidationContext();
		$ctx = $ctx->withReferenceTime(null)->withIssuer("issuer");
		$this->assertInstanceOf(ValidationContext::class, 
			$ctx->validate($this->_claims));
	}
	
	/**
	 * @expectedException JWX\JWT\Exception\ValidationException
	 */
	public function testValidateIssuerFails() {
		$ctx = new ValidationContext();
		$ctx = $ctx->withReferenceTime(null)->withIssuer("nope");
		$ctx->validate($this->_claims);
	}
	
	public function testValidateSubject() {
		$ctx = new ValidationContext();
		$ctx = $ctx->withReferenceTime(null)->withSubject("subject");
		$this->assertInstanceOf(ValidationContext::class, 
			$ctx->validate($this->_claims));
	}
	
	/**
	 * @expectedException JWX\JWT\Exception\ValidationException
	 */
	public function testValidateSubjectFails() {
		$ctx = new ValidationContext();
		$ctx = $ctx->withReferenceTime(null)->withSubject("nope");
		$ctx->validate($this->_claims);
	}
	
	public function testValidateAudience() {
		$ctx = new ValidationContext();
		$ctx = $ctx->withReferenceTime(null)->withAudience("test");
		$this->assertInstanceOf(ValidationContext::class, 
			$ctx->validate($this->_claims));
	}
	
	/**
	 * @expectedException JWX\JWT\Exception\ValidationException
	 */
	public function testValidateAudienceFails() {
		$ctx = new ValidationContext();
		$ctx = $ctx->withReferenceTime(null)->withAudience("nope");
		$ctx->validate($this->_claims);
	}
	
	public function testValidateID() {
		$ctx = new ValidationContext();
		$ctx = $ctx->withReferenceTime(null)->withID("id");
		$this->assertInstanceOf(ValidationContext::class, 
			$ctx->validate($this->_claims));
	}
	
	/**
	 * @expectedException JWX\JWT\Exception\ValidationException
	 */
	public function testValidateIDFails() {
		$ctx = new ValidationContext();
		$ctx = $ctx->withReferenceTime(null)->withID("nope");
		$ctx->validate($this->_claims);
	}
	
	public function testCustomClaim() {
		$claims = new Claims(new Claim("test", 0, new LessValidator()));
		$ctx = new ValidationContext(array("test" => 1));
		$this->assertInstanceOf(ValidationContext::class, 
			$ctx->validate($claims));
	}
	
	/**
	 * @expectedException JWX\JWT\Exception\ValidationException
	 */
	public function testCustomClaimFails() {
		$claims = new Claims(new Claim("test", 0, new LessValidator()));
		$ctx = new ValidationContext(array("test" => 0));
		$ctx->validate($claims);
	}
}