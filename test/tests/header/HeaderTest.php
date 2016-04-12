<?php

use JWX\JWT\Header;
use JWX\JWT\Parameter\TypeParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;
use JWX\JWT\Parameter\ContentTypeParameter;


/**
 * @group header
 */
class HeaderTest extends PHPUnit_Framework_TestCase
{
	/**
	 *
	 * @return Header
	 */
	public function testCreate() {
		$header = new Header(new TypeParameter("test"));
		$this->assertInstanceOf(Header::class, $header);
		return $header;
	}
	
	public function testCreateEmpty() {
		$header = new Header();
		$this->assertInstanceOf(Header::class, $header);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Header $header
	 */
	public function testHas(Header $header) {
		$this->assertTrue($header->has(RegisteredJWTParameter::PARAM_TYPE));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Header $header
	 */
	public function testGet(Header $header) {
		$param = $header->get(RegisteredJWTParameter::PARAM_TYPE);
		$this->assertInstanceOf(TypeParameter::class, $param);
	}
	
	/**
	 * @depends testCreate
	 * @expectedException LogicException
	 *
	 * @param Header $header
	 */
	public function testGetFails(Header $header) {
		$header->get("nope");
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Header $header
	 */
	public function testAdd(Header $header) {
		$header = $header->withParameters(new ContentTypeParameter("test"));
		$this->assertCount(2, $header);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Header $header
	 */
	public function testModify(Header $header) {
		$header = $header->withParameters(new TypeParameter("modified"));
		$this->assertEquals("modified", 
			$header->get(RegisteredJWTParameter::PARAM_TYPE)
				->value());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Header $header
	 * @return string
	 */
	public function testToJSON(Header $header) {
		$json = $header->toJSON();
		$this->assertEquals('{"typ":"test"}', $json);
		return $json;
	}
	
	/**
	 * @depends testToJSON
	 *
	 * @param string $json
	 * @return Header
	 */
	public function testFromJSON($json) {
		$header = Header::fromJSON($json);
		$this->assertInstanceOf(Header::class, $header);
		return $header;
	}
	
	/**
	 * @depends testCreate
	 * @depends testFromJSON
	 *
	 * @param Header $ref
	 * @param Header $recoded
	 */
	public function testRecode(Header $ref, Header $recoded) {
		$this->assertEquals($ref, $recoded);
	}
}
