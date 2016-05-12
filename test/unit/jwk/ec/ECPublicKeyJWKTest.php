<?php

use JWX\JWK\EC\ECPublicKeyJWK;
use JWX\JWK\JWK;


/**
 * @group jwk
 * @group ec
 */
class ECPublicKeyJWKTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$jwk = ECPublicKeyJWK::fromArray(
			array("kty" => "EC", "crv" => "", "x" => ""));
		$this->assertInstanceOf(JWK::class, $jwk);
		return $jwk;
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testCreateMissingParams() {
		new ECPublicKeyJWK();
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testCreateInvalidKeyType() {
		$params = array_fill_keys(ECPublicKeyJWK::MANAGED_PARAMS, "");
		$params["kty"] = "nope";
		ECPublicKeyJWK::fromArray($params);
	}
}
