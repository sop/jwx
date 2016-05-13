<?php

use JWX\JWK\JWK;
use JWX\JWK\Parameter\JWKParameter;


/**
 * @group jwk
 */
class JWKTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$jwk = JWK::fromArray(array("test" => "value", "another" => "more"));
		$this->assertInstanceOf(JWK::class, $jwk);
		return $jwk;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWK $jwk
	 */
	public function testHas(JWK $jwk) {
		$this->assertTrue($jwk->has("test"));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWK $jwk
	 */
	public function testHasMulti(JWK $jwk) {
		$this->assertTrue($jwk->has("test", "another"));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWK $jwk
	 */
	public function testHasMultiFails(JWK $jwk) {
		$this->assertFalse($jwk->has("test", "nope"));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWK $jwk
	 */
	public function testGet(JWK $jwk) {
		$param = $jwk->get("test");
		$this->assertInstanceOf(JWKParameter::class, $param);
	}
	
	/**
	 * @depends testCreate
	 * @expectedException LogicException
	 *
	 * @param JWK $jwk
	 */
	public function testGetFails(JWK $jwk) {
		$jwk->get("nope");
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWK $jwk
	 */
	public function testWithParameters(JWK $jwk) {
		$jwk = $jwk->withParameters(new JWKParameter("k", "v"));
		$this->assertTrue($jwk->has("k"));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWK $jwk
	 */
	public function testGetParameters(JWK $jwk) {
		$params = $jwk->parameters();
		$this->assertContainsOnlyInstancesOf(JWKParameter::class, $params);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWK $jwk
	 */
	public function testCount(JWK $jwk) {
		$this->assertCount(2, $jwk);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWK $jwk
	 */
	public function testIterator(JWK $jwk) {
		$values = array();
		foreach ($jwk as $param) {
			$values[] = $param;
		}
		$this->assertContainsOnlyInstancesOf(JWKParameter::class, $values);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWK $jwk
	 */
	public function testToJSON(JWK $jwk) {
		$json = $jwk->toJSON();
		$this->assertJson($json);
		return $json;
	}
	
	public function testToEmptyJSON() {
		$jwk = new JWK();
		$this->assertEquals("", $jwk->toJSON());
	}
	
	/**
	 * @depends testToJSON
	 *
	 * @param string $json
	 */
	public function testFromJSON($json) {
		$jwk = JWK::fromJSON($json);
		$this->assertInstanceOf(JWK::class, $jwk);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidJSON() {
		JWK::fromJSON("null");
	}
}
