<?php

use CryptoUtil\ASN1\PrivateKey;
use CryptoUtil\ASN1\PrivateKeyInfo;
use CryptoUtil\PEM\PEM;
use JWX\JWK\Asymmetric\PrivateKeyJWK;


/**
 * @group jwk
 * @group asymmetric
 */
class PrivateKeyJWKTest extends PHPUnit_Framework_TestCase
{
	public function testFromRSA() {
		$pki = PrivateKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem"));
		$jwk = PrivateKeyJWK::fromPrivateKeyInfo($pki);
		$this->assertInstanceOf(PrivateKeyJWK::class, $jwk);
	}
	
	public function testFromEC() {
		$pki = PrivateKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/ec/private_key_P-256.pem"));
		$jwk = PrivateKeyJWK::fromPrivateKeyInfo($pki);
		$this->assertInstanceOf(PrivateKeyJWK::class, $jwk);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testUnsupportedKey() {
		PrivateKeyJWK::fromPrivateKey(new PrivateKeyJWKTest_UnsupportedKey());
	}
}


class PrivateKeyJWKTest_UnsupportedKey extends PrivateKey
{
	public function privateKeyInfo() {

	}
	
	public function publicKey() {

	}
	
	public function toDER() {

	}
	
	public function toPEM() {

	}
}
