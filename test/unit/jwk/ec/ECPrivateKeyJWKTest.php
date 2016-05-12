<?php

use JWX\JWK\EC\ECPrivateKeyJWK;
use JWX\JWK\JWK;


/**
 * @group jwk
 * @group ec
 */
class ECPrivateKeyJWKTest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$jwk = ECPrivateKeyJWK::fromArray(
			array("kty" => "EC", "crv" => "", "x" => "", "d" => ""));
		$this->assertInstanceOf(JWK::class, $jwk);
		return $jwk;
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testCreateMissingParams() {
		new ECPrivateKeyJWK();
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testCreateInvalidKeyType() {
		$params = array_fill_keys(ECPrivateKeyJWK::MANAGED_PARAMS, "");
		$params["kty"] = "nope";
		ECPrivateKeyJWK::fromArray($params);
	}
}
