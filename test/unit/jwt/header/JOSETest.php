<?php

use JWX\JWA\JWA;
use JWX\JWT\Header\Header;
use JWX\JWT\Header\JOSE;
use JWX\JWT\Parameter\ContentTypeParameter;
use JWX\JWT\Parameter\JWTParameter;
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
		$this->assertTrue($jose->has(JWTParameter::PARAM_TYPE));
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
	
	public function testIsJWS() {
		$jose = new JOSE(Header::fromArray(array("alg" => JWA::ALGO_HS256)));
		$this->assertTrue($jose->isJWS());
		$this->assertFalse($jose->isJWE());
	}
	
	public function testIsJWE() {
		$jose = new JOSE(
			Header::fromArray(array("enc" => JWA::ALGO_A128CBC_HS256)));
		$this->assertTrue($jose->isJWE());
		$this->assertFalse($jose->isJWS());
	}
}
