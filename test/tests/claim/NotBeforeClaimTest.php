<?php

use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\RegisteredClaim;
use JWX\JWT\Claim\NotBeforeClaim;


/**
 * @group claim
 */
class NotBeforeClaimTest extends PHPUnit_Framework_TestCase
{
	const VALUE = 1460703960;
	
	public function testCreate() {
		$claim = new NotBeforeClaim(self::VALUE);
		$this->assertEquals(RegisteredClaim::NAME_NOT_BEFORE, $claim->name());
	}
	
	/**
	 * @dataProvider validateProvider
	 */
	public function testValidate($constraint, $result) {
		$claim = NotBeforeClaim::fromJSONValue(self::VALUE);
		$this->assertEquals($result, $claim->validate($constraint));
	}
	
	public function validateProvider() {
		// @formatter:off
		return array(
			[self::VALUE, true],
			[self::VALUE + 1, true],
			[self::VALUE - 1, false]
		);
		// @formatter:on
	}
}
