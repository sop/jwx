<?php

use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\RegisteredClaim;
use JWX\JWT\Claim\IssuedAtClaim;


/**
 * @group claim
 */
class IssuedAtClaimTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$claim = IssuedAtClaim::now();
		$this->assertEquals(RegisteredClaim::NAME_ISSUED_AT, $claim->name());
	}
}
