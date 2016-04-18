<?php

use JWX\JWS\JWS;
use JWX\JWS\Algorithm\HS256Algorithm;
use JWX\JWT\Header;
use JWX\JWT\Parameter\B64PayloadParameter;


/**
 * @group jws
 */
class B64Test extends PHPUnit_Framework_TestCase
{
	const PAYLOAD = "PAYLOAD";
	
	const SECRET = "SECRETKEY";
	
	/**
	 *
	 * @return JWS
	 */
	public function testCreate() {
		$jws = JWS::sign(self::PAYLOAD, new HS256Algorithm(self::SECRET), 
			new Header(new B64PayloadParameter(false)));
		$this->assertInstanceOf(JWS::class, $jws);
		return $jws;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWS $jws
	 */
	public function testValidate(JWS $jws) {
		$this->assertTrue($jws->validate(new HS256Algorithm(self::SECRET)));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWS $jws
	 */
	public function testRecode(JWS $jws) {
		$data = $jws->toCompact();
		$result = JWS::fromCompact($data);
		$this->assertInstanceOf(JWS::class, $result);
		return $result;
	}
	
	/**
	 * @depends testRecode
	 *
	 * @param JWS $jws
	 */
	public function testRecodedPayload(JWS $jws) {
		$this->assertEquals(self::PAYLOAD, $jws->payload());
	}
}
