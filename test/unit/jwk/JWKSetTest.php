<?php

use JWX\JWK\JWK;
use JWX\JWK\JWKSet;


/**
 * @group jwk
 */
class JWKSetTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$jwkset = new JWKSet(JWK::fromArray(["kid" => "key1"]), 
			JWK::fromArray(["kid" => "key2"]));
		$this->assertInstanceOf(JWKSet::class, $jwkset);
		return $jwkset;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKSet $jwkset
	 */
	public function testHasKeyID(JWKSet $jwkset) {
		$this->assertTrue($jwkset->hasKeyID("key1"));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKSet $jwkset
	 */
	public function testHasNotKeyID(JWKSet $jwkset) {
		$this->assertFalse($jwkset->hasKeyID("key3"));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKSet $jwkset
	 */
	public function testByKeyID(JWKSet $jwkset) {
		$jwk = $jwkset->byKeyID("key1");
		$this->assertInstanceOf(JWK::class, $jwk);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKSet $jwkset
	 */
	public function testToJSON(JWKSet $jwkset) {
		$json = $jwkset->toJSON();
		$this->assertTrue(is_string($json));
		return $json;
	}
	
	/**
	 * @depends testToJSON
	 *
	 * @param string $json
	 */
	public function testFromJSON($json) {
		$jwkset = JWKSet::fromJSON($json);
		$this->assertInstanceOf(JWKSet::class, $jwkset);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKSet $jwkset
	 */
	public function testCount(JWKSet $jwkset) {
		$this->assertCount(2, $jwkset);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWKSet $jwkset
	 */
	public function testIterator(JWKSet $jwkset) {
		$values = array();
		foreach ($jwkset as $jwk) {
			$values[] = $jwk;
		}
		$this->assertCount(2, $values);
	}
}
