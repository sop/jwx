<?php

use JWX\JWK\Asymmetric\PublicKeyJWK;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\PublicKey;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;

/**
 * @group jwk
 * @group asymmetric
 */
class PublicKeyJWKTest extends PHPUnit_Framework_TestCase
{
    public function testFromRSA()
    {
        $pki = PublicKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem"));
        $jwk = PublicKeyJWK::fromPublicKeyInfo($pki);
        $this->assertInstanceOf(PublicKeyJWK::class, $jwk);
    }
    
    public function testFromEC()
    {
        $pki = PublicKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/ec/public_key_P-256.pem"));
        $jwk = PublicKeyJWK::fromPublicKeyInfo($pki);
        $this->assertInstanceOf(PublicKeyJWK::class, $jwk);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testUnsupportedKey()
    {
        PublicKeyJWK::fromPublicKey(new PublicKeyJWKTest_UnsupportedKey());
    }
}

class PublicKeyJWKTest_UnsupportedKey extends PublicKey
{
    public function publicKeyInfo()
    {
    }
    
    public function toDER()
    {
    }
    
    public function algorithmIdentifier()
    {
    }

}
