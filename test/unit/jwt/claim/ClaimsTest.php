<?php

use JWX\JWT\Claim\AudienceClaim;
use JWX\JWT\Claim\Claim;
use JWX\JWT\Claim\IssuerClaim;
use JWX\JWT\Claim\RegisteredClaim;
use JWX\JWT\Claim\SubjectClaim;
use JWX\JWT\Claims;


/**
 * @group jwt
 * @group claim
 */
class ClaimsTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$claims = new Claims(new IssuerClaim("issuer"), 
			new SubjectClaim("subject"), new AudienceClaim("test"));
		$this->assertInstanceOf(Claims::class, $claims);
		return $claims;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @return string
	 */
	public function testToJSON(Claims $claims) {
		$json = $claims->toJSON();
		$this->assertTrue(is_string($json));
		return $json;
	}
	
	/**
	 * @depends testToJSON
	 *
	 * @param string $json
	 */
	public function testFromJSON($json) {
		$claims = Claims::fromJSON($json);
		$this->assertInstanceOf(Claims::class, $claims);
		return $claims;
	}
	
	/**
	 * @depends testCreate
	 * @depends testFromJSON
	 *
	 * @param Claims $ref
	 * @param Claims $claims
	 */
	public function testRecoded(Claims $ref, Claims $claims) {
		$this->assertEquals($ref, $claims);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @return string
	 */
	public function testHas(Claims $claims) {
		$this->assertTrue($claims->has(RegisteredClaim::NAME_ISSUER));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @return string
	 */
	public function testGet(Claims $claims) {
		$this->assertInstanceOf(Claim::class, 
			$claims->get(RegisteredClaim::NAME_ISSUER));
	}
	
	/**
	 * @depends testCreate
	 * @expectedException LogicException
	 *
	 * @return string
	 */
	public function testGetFails(Claims $claims) {
		$claims->get("nope");
	}
	
	/**
	 * @depends testCreate
	 *
	 * @return string
	 */
	public function testGetClaims(Claims $claims) {
		$this->assertTrue(is_array($claims->all()));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @return string
	 */
	public function testCount(Claims $claims) {
		$this->assertCount(3, $claims);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @return string
	 */
	public function testIterator(Claims $claims) {
		$values = array();
		foreach ($claims as $claim) {
			$values[] = $claim;
		}
		$this->assertCount(3, $values);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @return string
	 */
	public function testWithClaims(Claims $claims) {
		$claims = $claims->withClaims(new Claim("name", "value"));
		$this->assertCount(4, $claims);
	}
}
