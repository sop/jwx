<?php

use JWX\JWT\Claims;
use JWX\JWT\Claim\IssuerClaim;
use JWX\JWT\Claim\SubjectClaim;
use JWX\JWS\Algorithm\HS256Algorithm;
use JWX\Header\Header;
use JWX\JWS\JWS;
use JWX\JWS\Algorithm\NoneAlgorithm;
use JWX\JWS\Algorithm\HS384Algorithm;
use JWX\JWS\Algorithm\HS512Algorithm;


/**
 * @group jws
 */
class HMACTest extends PHPUnit_Framework_TestCase
{
	protected $_claims;
	
	const SECRET = "SECRETKEY";
	
	public function setUp() {
		$this->_claims = new Claims(new IssuerClaim("test"), 
			new SubjectClaim("test"));
	}
	
	public function tearDown() {
		$this->_claims = null;
	}
	
	/**
	 *
	 * @return JWS
	 */
	public function testSignHS256() {
		$jws = JWS::sign($this->_claims->toJSON(), new Header(), 
			new HS256Algorithm(self::SECRET));
		$this->assertInstanceOf(JWS::class, $jws);
		return $jws;
	}
	
	/**
	 * @depends testSignHS256
	 *
	 * @param JWS $jws
	 */
	public function testValidateHS256(JWS $jws) {
		$this->assertTrue($jws->validate(new HS256Algorithm(self::SECRET)));
	}
	
	/**
	 * @depends testSignHS256
	 *
	 * @param JWS $jws
	 */
	public function testValidateHS256InvalidKey(JWS $jws) {
		$this->assertFalse($jws->validate(new HS256Algorithm("nope")));
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
		$jws = JWS::sign($this->_claims->toJSON(), new Header(), 
			new HS384Algorithm(self::SECRET));
		$this->assertInstanceOf(JWS::class, $jws);
		return $jws;
	}
	
	/**
	 * @depends testSignHS384
	 *
	 * @param JWS $jws
	 */
	public function testValidateHS384(JWS $jws) {
		$this->assertTrue($jws->validate(new HS384Algorithm(self::SECRET)));
	}
	
	/**
	 *
	 * @return JWS
	 */
	public function testSignHS512() {
		$jws = JWS::sign($this->_claims->toJSON(), new Header(), 
			new HS512Algorithm(self::SECRET));
		$this->assertInstanceOf(JWS::class, $jws);
		return $jws;
	}
	
	/**
	 * @depends testSignHS512
	 *
	 * @param JWS $jws
	 */
	public function testValidateHS512(JWS $jws) {
		$this->assertTrue($jws->validate(new HS512Algorithm(self::SECRET)));
	}
}
