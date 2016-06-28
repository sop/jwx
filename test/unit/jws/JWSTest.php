<?php

use JWX\JWA\JWA;
use JWX\JWK\JWKSet;
use JWX\JWK\Parameter\KeyIDParameter as JWKID;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWS\Algorithm\HS256Algorithm;
use JWX\JWS\Algorithm\NoneAlgorithm;
use JWX\JWS\JWS;
use JWX\JWT\Header\Header;
use JWX\JWT\Header\JOSE;
use JWX\JWT\Parameter\B64PayloadParameter;
use JWX\JWT\Parameter\CriticalParameter;
use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\KeyIDParameter as JWTID;


/**
 * @group jws
 */
class JWSTest extends PHPUnit_Framework_TestCase
{
	const KEY = "12345678";
	
	const KEY_ID = "id";
	
	const PAYLOAD = "PAYLOAD";
	
	private static $_signAlgo;
	
	public static function setUpBeforeClass() {
		self::$_signAlgo = new HS256Algorithm(self::KEY);
	}
	
	public static function tearDownAfterClass() {
		self::$_signAlgo = null;
	}
	
	public function testCreate() {
		$jws = JWS::sign(self::PAYLOAD, self::$_signAlgo, 
			new Header(new JWTID(self::KEY_ID)));
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
	public function testValidateWithJWK(JWS $jws) {
		$jwk = SymmetricKeyJWK::fromKey(self::KEY);
		$this->assertTrue($jws->validateWithJWK($jwk));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param JWS $jws
	 */
	public function testValidateWithJWKSet(JWS $jws) {
		$jwk = SymmetricKeyJWK::fromKey(self::KEY)->withParameters(
			new JWKID(self::KEY_ID));
		$this->assertTrue($jws->validateWithJWKSet(new JWKSet($jwk)));
	}
	
	/**
	 * @depends testCreate
	 * @expectedException RuntimeException
	 *
	 * @param JWS $jws
	 */
	public function testValidateWithJWKSetNoKeys(JWS $jws) {
		$jws->validateWithJWKSet(new JWKSet());
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
	
	public function testSignWithB64Param() {
		$header = new Header(new B64PayloadParameter(true));
		$jws = JWS::sign(self::PAYLOAD, self::$_signAlgo, $header);
		$this->assertInstanceOf(JWS::class, $jws);
		return $jws;
	}
	
	public function testSignWithB64ParamAsCritical() {
		$header = new Header(new B64PayloadParameter(true), 
			new CriticalParameter(JWTParameter::P_CRIT));
		$jws = JWS::sign(self::PAYLOAD, self::$_signAlgo, $header);
		$this->assertInstanceOf(JWS::class, $jws);
	}
	
	/**
	 * @depends testSignWithB64Param
	 *
	 * @param JWS $jws
	 */
	public function testToCompactWithB64Param(JWS $jws) {
		$this->assertInternalType("string", $jws->toCompact());
	}
}
