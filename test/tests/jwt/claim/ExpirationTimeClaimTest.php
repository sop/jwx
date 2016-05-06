<?php

use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\ExpirationTimeClaim;
use JWX\JWT\Claim\RegisteredClaim;


/**
 * @group jwt
 * @group claim
 */
class ExpirationTimeClaimTest extends PHPUnit_Framework_TestCase
{
	const VALUE = 1460703960;
	
	public function testCreate() {
		$claim = new ExpirationTimeClaim(self::VALUE);
		$this->assertInstanceOf(ExpirationTimeClaim::class, $claim);
		return $claim;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Claim $claim
	 */
	public function testClaimName(Claim $claim) {
		$this->assertEquals(RegisteredClaim::NAME_EXPIRATION_TIME, 
			$claim->name());
	}
	
	/**
	 * @dataProvider validateProvider
	 */
	public function testValidate($constraint, $result) {
		$claim = ExpirationTimeClaim::fromJSONValue(self::VALUE);
		$this->assertEquals($result, $claim->validate($constraint));
	}
	
	public function validateProvider() {
		return array(
			/* @formatter:off */
			[self::VALUE - 1, true],
			[self::VALUE, false],
			[self::VALUE + 1, false]
			/* @formatter:on */
		);
	}
}
