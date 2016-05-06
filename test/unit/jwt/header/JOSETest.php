<?php

use JWX\JWT\Header;
use JWX\JWT\JOSE;
use JWX\JWT\Parameter\ContentTypeParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;
use JWX\JWT\Parameter\TypeParameter;


/**
 * @group jwt
 * @group header
 */
class JOSETest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$jose = new JOSE(new Header(new TypeParameter("test")));
		$this->assertInstanceOf(JOSE::class, $jose);
		return $jose;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JOSE $jose
	 */
	public function testHas(JOSE $jose) {
		$this->assertTrue($jose->has(RegisteredJWTParameter::PARAM_TYPE));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JOSE $jose
	 */
	public function testMerge(JOSE $jose) {
		$jose = $jose->withHeader(new Header(new ContentTypeParameter("test")));
		$this->assertInstanceOf(JOSE::class, $jose);
		return $jose;
	}
	
	/**
	 * @depends testMerge
	 *
	 * @param JOSE $jose
	 */
	public function testMergedCount(JOSE $jose) {
		$this->assertCount(2, $jose);
	}
	
	/**
	 * @depends testCreate
	 * @expectedException RuntimeException
	 *
	 * @param JOSE $jose
	 */
	public function testDuplicateFail(JOSE $jose) {
		$jose->withHeader(new Header(new TypeParameter("dup")));
	}
}
