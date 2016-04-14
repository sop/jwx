<?php

use JWX\JWT\Header;
use JWX\JWS\JWS;
use JWX\JWS\Algorithm\NoneAlgorithm;
use JWX\JWT\Claims;
use JWX\JWT\Claim\IssuerClaim;
use JWX\JWT\Claim\SubjectClaim;


/**
 * @group jws
 */
class NoneTest extends PHPUnit_Framework_TestCase
{
	protected $_claims;
	
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
	public function testCreate() {
		$jws = JWS::sign($this->_claims->toJSON(), new Header(), 
			new NoneAlgorithm());
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
		$this->assertEquals($this->_claims, Claims::fromJSON($jws->payload()));
	}
}
