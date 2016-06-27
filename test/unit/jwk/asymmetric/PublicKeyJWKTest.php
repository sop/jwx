<?php

use CryptoUtil\ASN1\PublicKey;
use CryptoUtil\ASN1\PublicKeyInfo;
use CryptoUtil\PEM\PEM;
use JWX\JWK\Asymmetric\PublicKeyJWK;


/**
 * @group jwk
 * @group asymmetric
 */
class PublicKeyJWKTest extends PHPUnit_Framework_TestCase
{
	public function testFromRSA() {
		$pki = PublicKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem"));
		$jwk = PublicKeyJWK::fromPublicKeyInfo($pki);
		$this->assertInstanceOf(PublicKeyJWK::class, $jwk);
	}
	
	public function testFromEC() {
		$pki = PublicKeyInfo::fromPEM(
			PEM::fromFile(TEST_ASSETS_DIR . "/ec/public_key_P-256.pem"));
		$jwk = PublicKeyJWK::fromPublicKeyInfo($pki);
		$this->assertInstanceOf(PublicKeyJWK::class, $jwk);
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testUnsupportedKey() {
		PublicKeyJWK::fromPublicKey(new PublicKeyJWKTest_UnsupportedKey());
	}
}


class PublicKeyJWKTest_UnsupportedKey extends PublicKey
{
	public function publicKeyInfo() {

	}
	
	public function toDER() {

	}
}
