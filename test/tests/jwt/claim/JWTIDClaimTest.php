<?php

use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\RegisteredClaim;
use JWX\JWT\Claim\JWTIDClaim;


/**
 * @group claim
 */
class JWTIDTest extends PHPUnit_Framework_TestCase
{
	const VALUE = "uuid";
	
	public function testCreate() {
		$claim = new JWTIDClaim(self::VALUE);
		$this->assertEquals(RegisteredClaim::NAME_JWT_ID, $claim->name());
	}
	
	/**
	 * @dataProvider validateProvider
	 */
	public function testValidate($constraint, $result) {
		$claim = JWTIDClaim::fromJSONValue(self::VALUE);
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
