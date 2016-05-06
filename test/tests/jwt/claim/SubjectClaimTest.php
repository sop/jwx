<?php

use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\SubjectClaim;
use JWX\JWT\Claim\RegisteredClaim;


/**
 * @group claim
 */
class SubjectClaimTest extends PHPUnit_Framework_TestCase
{
	const VALUE = "subject";
	
	public function testCreate() {
		$claim = new SubjectClaim(self::VALUE);
		$this->assertEquals(RegisteredClaim::NAME_SUBJECT, $claim->name());
	}
	
	/**
	 * @dataProvider validateProvider
	 */
	public function testValidate($constraint, $result) {
		$claim = SubjectClaim::fromJSONValue(self::VALUE);
		$this->assertEquals($result, $claim->validate($constraint));
	}
	
	public function validateProvider() {
		// @formatter:off
		return array(
			[self::VALUE, true],
			["nope", false]
		);
		// @formatter:on
	}
}
