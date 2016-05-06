<?php

use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\RegisteredClaim;
use JWX\JWT\Claim\AudienceClaim;


/**
 * @group claim
 */
class AudienceClaimTest extends PHPUnit_Framework_TestCase
{
	const VALUE_SINGLE = "audience";
	const VALUE_MANY = array("audience #1", "audience #2");
	
	public function testCreate() {
		$claim = new AudienceClaim(self::VALUE_SINGLE);
		$this->assertEquals(RegisteredClaim::NAME_AUDIENCE, $claim->name());
	}
	
	/**
	 * @dataProvider validateProvider
	 */
	public function testValidate($value, $constraint, $result) {
		$claim = AudienceClaim::fromJSONValue($value);
		$this->assertEquals($result, $claim->validate($constraint));
	}
	
	public function validateProvider() {
		// @formatter:off
		return array(
			[self::VALUE_SINGLE, self::VALUE_SINGLE, true],
			[self::VALUE_SINGLE, "nope", false],
			[self::VALUE_MANY, self::VALUE_MANY[1], true],
			[self::VALUE_MANY, "nope", false]
		);
		// @formatter:on
	}
}
