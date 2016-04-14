<?php

use JWX\JWS\JWS;
use JWX\JWS\Algorithm\NoneAlgorithm;


/**
 * @group jws
 */
class NoneSignatureTest extends PHPUnit_Framework_TestCase
{
	const PAYLOAD = "PAYLOAD";
	
	/**
	 *
	 * @return JWS
	 */
	public function testCreate() {
		$jws = JWS::sign(self::PAYLOAD, new NoneAlgorithm());
		$this->assertInstanceOf(JWS::class, $jws);
		return $jws;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWS $jws
	 */
	public function testValidate(JWS $jws) {
		$this->assertTrue($jws->validate(new NoneAlgorithm()));
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
