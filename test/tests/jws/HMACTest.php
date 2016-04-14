<?php

use JWX\JWS\JWS;
use JWX\JWS\Algorithm\NoneAlgorithm;
use JWX\JWS\Algorithm\HS256Algorithm;
use JWX\JWS\Algorithm\HS384Algorithm;
use JWX\JWS\Algorithm\HS512Algorithm;


/**
 * @group jws
 */
class HMACTest extends PHPUnit_Framework_TestCase
{
	const PAYLOAD = "PAYLOAD";
	
	const SECRET = "SECRETKEY";
	
	/**
	 *
	 * @return JWS
	 */
	public function testSignHS256() {
		$algo = new HS256Algorithm(self::SECRET);
		$jws = JWS::sign(self::PAYLOAD, $algo);
		$this->assertInstanceOf(JWS::class, $jws);
		return $jws;
	}
	
	/**
	 * @depends testSignHS256
	 *
	 * @param JWS $jws
	 */
	public function testValidateHS256(JWS $jws) {
		$algo = new HS256Algorithm(self::SECRET);
		$this->assertTrue($jws->validate($algo));
	}
	
	/**
	 * @depends testSignHS256
	 *
	 * @param JWS $jws
	 */
	public function testValidateHS256InvalidKey(JWS $jws) {
		$algo = new HS256Algorithm("nope");
		$this->assertFalse($jws->validate($algo));
	}
	
	/**
	 * @depends testSignHS256
	 * @expectedException RuntimeException
	 *
	 * @param JWS $jws
	 */
	public function testFailInvalidAlgorithm(JWS $jws) {
		$jws->validate(new NoneAlgorithm());
	}
	
	/**
	 *
	 * @return JWS
	 */
	public function testSignHS384() {
		$algo = new HS384Algorithm(self::SECRET);
		$jws = JWS::sign(self::PAYLOAD, $algo);
		$this->assertInstanceOf(JWS::class, $jws);
		return $jws;
	}
	
	/**
	 * @depends testSignHS384
	 *
	 * @param JWS $jws
	 */
	public function testValidateHS384(JWS $jws) {
		$algo = new HS384Algorithm(self::SECRET);
		$this->assertTrue($jws->validate($algo));
	}
	
	/**
	 *
	 * @return JWS
	 */
	public function testSignHS512() {
		$algo = new HS512Algorithm(self::SECRET);
		$jws = JWS::sign(self::PAYLOAD, $algo);
		$this->assertInstanceOf(JWS::class, $jws);
		return $jws;
	}
	
	/**
	 * @depends testSignHS512
	 *
	 * @param JWS $jws
	 */
	public function testValidateHS512(JWS $jws) {
		$algo = new HS512Algorithm(self::SECRET);
		$this->assertTrue($jws->validate($algo));
	}
}
