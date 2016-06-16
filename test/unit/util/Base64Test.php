<?php

use JWX\Util\Base64;


/**
 * @group util
 * @group base64
 */
class Base64Test extends PHPUnit_Framework_TestCase
{
	const DATA = "My hovercraft is full of eels.";
	
	public function testEncode() {
		$data = Base64::encode(self::DATA);
		$this->assertInternalType("string", $data);
		return $data;
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $data
	 */
	public function testIsValidEncoding($data) {
		$this->assertTrue(Base64::isValid($data));
	}
	
	/**
	 * @depends testEncode
	 *
	 * @param string $data
	 */
	public function testDecode($data) {
		$result = Base64::decode($data);
		$this->assertEquals(self::DATA, $result);
	}
	
	public function isNotValidEncoding() {
		$this->assertFalse(Base64::isValid("#"));
	}
	
	public function testURLEncode() {
		$data = Base64::urlEncode(self::DATA);
		$this->assertInternalType("string", $data);
		return $data;
	}
	
	/**
	 * @depends testURLEncode
	 *
	 * @param string $data
	 */
	public function testIsValidURLEncoding($data) {
		$this->assertTrue(Base64::isValidURLEncoding($data));
	}
	
	/**
	 * @depends testURLEncode
	 *
	 * @param string $data
	 */
	public function testURLDecode($data) {
		$result = Base64::urlDecode($data);
		$this->assertEquals(self::DATA, $result);
	}
	
	public function testIsNotValidURLEncoding() {
		$this->assertFalse(Base64::isValidURLEncoding("#"));
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testURLDecodeFail() {
		Base64::urlDecode("x");
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testDecodeFail() {
		Base64::decode("#");
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testEncodeFail() {
		Base64::encode(new stdClass());
	}
}
