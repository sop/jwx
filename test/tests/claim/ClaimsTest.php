<?php

use JWX\JWT\Claims;
use JWX\JWT\Claim\IssuerClaim;
use JWX\JWT\Claim\SubjectClaim;
use JWX\JWT\Claim\AudienceClaim;


/**
 * @group claim
 */
class ClaimsTest extends PHPUnit_Framework_TestCase
{
	protected $_claims;
	
	public function setUp() {
		$this->_claims = new Claims(new IssuerClaim("issuer"), 
			new SubjectClaim("subject"), new AudienceClaim("test"));
	}
	
	public function tearDown() {
		$this->_claims = null;
	}
	
	/**
	 *
	 * @return string
	 */
	public function testCreateJSON() {
		$json = $this->_claims->toJSON();
		$this->assertTrue(is_string($json));
		return $json;
	}
	
	/**
	 * @depends testCreateJSON
	 *
	 * @param string $json
	 */
	public function testFromJSON($json) {
		$claims = Claims::fromJSON($json);
		$this->assertInstanceOf(Claims::class, $claims);
		return $claims;
	}
	
	/**
	 * @depends testFromJSON
	 *
	 * @param Claims $claims
	 */
	public function testRecoded(Claims $claims) {
		$this->assertEquals($this->_claims, $claims);
	}
}
