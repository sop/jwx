<?php

use JWX\JWA\JWA;
use JWX\JWS\Algorithm\HS256Algorithm;
use JWX\JWS\Algorithm\NoneAlgorithm;
use JWX\JWS\JWS;
use JWX\JWT\JOSE;


/**
 * @group jws
 */
class JWSTest extends PHPUnit_Framework_TestCase
{
	const KEY = "12345678";
	const PAYLOAD = "PAYLOAD";
	
	private static $_signAlgo;
	
	public static function setUpBeforeClass() {
		self::$_signAlgo = new HS256Algorithm(self::KEY);
	}
	
	public static function tearDownAfterClass() {
		self::$_signAlgo = null;
	}
	
	public function testCreate() {
		$jws = JWS::sign(self::PAYLOAD, self::$_signAlgo);
		$this->assertInstanceOf(JWS::class, $jws);
		return $jws;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWS $jws
	 */
	public function testValidate(JWS $jws) {
		$this->assertTrue($jws->validate(self::$_signAlgo));
	}
	
	/**
	 * @depends testCreate
	 * @expectedException UnexpectedValueException
	 *
	 * @param JWS $jws
	 */
	public function testValidateInvalidAlgo(JWS $jws) {
		$jws->validate(new NoneAlgorithm());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWS $jws
	 */
	public function testHeader(JWS $jws) {
		$header = $jws->header();
		$this->assertInstanceOf(JOSE::class, $header);
		return $header;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWS $jws
	 */
	public function testAlgoName(JWS $jws) {
		$this->assertEquals(JWA::ALGO_HS256, $jws->algorithmName());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWS $jws
	 */
	public function testPayload(JWS $jws) {
		$this->assertEquals(self::PAYLOAD, $jws->payload());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWS $jws
	 */
	public function testSignature(JWS $jws) {
		$this->assertInternalType("string", $jws->signature());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWS $jws
	 */
	public function testToCompact(JWS $jws) {
		$data = $jws->toCompact();
		$this->assertInternalType("string", $data);
		return $data;
	}
	
	/**
	 * @depends testToCompact
	 *
	 * @param string $data
	 */
	public function testFromCompact($data) {
		$jws = JWS::fromCompact($data);
		$this->assertInstanceOf(JWS::class, $jws);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWS $jws
	 */
	public function testToCompactDetached(JWS $jws) {
		$data = $jws->toCompactDetached();
		$this->assertInternalType("string", $data);
		return $data;
	}
	
	/**
	 * @depends testToCompactDetached
	 *
	 * @param string $data
	 */
	public function testFromCompactDetached($data) {
		$jws = JWS::fromCompact($data);
		$this->assertInstanceOf(JWS::class, $jws);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testFromPartsFail() {
		JWS::fromParts(array());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWS $jws
	 */
	public function testToString(JWS $jws) {
		$data = strval($jws);
		$this->assertInternalType("string", $data);
	}
}
