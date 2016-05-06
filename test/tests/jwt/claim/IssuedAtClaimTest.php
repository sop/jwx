<?php

use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\IssuedAtClaim;
use JWX\JWT\Claim\RegisteredClaim;


/**
 * @group jwt
 * @group claim
 */
class IssuedAtClaimTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$claim = IssuedAtClaim::now();
		$this->assertInstanceOf(IssuedAtClaim::class, $claim);
		return $claim;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Claim $claim
	 */
	public function testClaimName(Claim $claim) {
		$this->assertEquals(RegisteredClaim::NAME_ISSUED_AT, $claim->name());
	}
}
