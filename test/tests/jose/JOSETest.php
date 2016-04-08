<?php

use JWX\JOSE\JOSE;
use JWX\JOSE\Parameter\TypeParameter;
use JWX\JOSE\Parameter\RegisteredParameter;


/**
 * @group jose
 */
class JOSETest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$jose = new JOSE(new TypeParameter("test"));
		$this->assertInstanceOf('JWX\JOSE\JOSE', $jose);
		return $jose;
	}
	
	public function testCreateEmpty() {
		$jose = new JOSE();
		$this->assertInstanceOf('JWX\JOSE\JOSE', $jose);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JOSE $jose
	 */
	public function testHas(JOSE $jose) {
		$this->assertTrue($jose->has(RegisteredParameter::NAME_TYPE));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JOSE $jose
	 */
	public function testGet(JOSE $jose) {
		$param = $jose->get(RegisteredParameter::NAME_TYPE);
		$this->assertInstanceOf('JWX\JOSE\Parameter\TypeParameter', $param);
	}
	
	/**
	 * @depends testCreate
	 * @expectedException LogicException
	 *
	 * @param JOSE $jose
	 */
	public function testGetFails(JOSE $jose) {
		$jose->get("nope");
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JOSE $jose
	 */
	public function testToJSON(JOSE $jose) {
		$json = $jose->toJSON();
		$this->assertEquals('{"typ":"test"}', $json);
		return $json;
	}
	
	/**
	 * @depends testToJSON
	 *
	 * @param unknown $json
	 */
	public function testFromJSON($json) {
		$jose = JOSE::fromJSON($json);
		$this->assertInstanceOf('JWX\JOSE\JOSE', $jose);
		return $jose;
	}
	
	/**
	 * @depends testCreate
	 * @depends testFromJSON
	 *
	 * @param JOSE $ref
	 * @param JOSE $recoded
	 */
	public function testRecode(JOSE $ref, JOSE $recoded) {
		$this->assertEquals($ref, $recoded);
	}
}
