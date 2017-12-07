<?php

use JWX\JWK\Asymmetric\PrivateKeyJWK;
use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Asymmetric\PublicKey;

/**
 * @group jwk
 * @group asymmetric
 */
class PrivateKeyJWKTest extends TestCase
{
    public function testFromRSA()
    {
        $pki = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/rsa/private_key.pem"));
        $jwk = PrivateKeyJWK::fromPrivateKeyInfo($pki);
        $this->assertInstanceOf(PrivateKeyJWK::class, $jwk);
    }
    
    public function testFromEC()
    {
        $pki = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/ec/private_key_P-256.pem"));
        $jwk = PrivateKeyJWK::fromPrivateKeyInfo($pki);
        $this->assertInstanceOf(PrivateKeyJWK::class, $jwk);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testUnsupportedKey()
    {
        PrivateKeyJWK::fromPrivateKey(new PrivateKeyJWKTest_UnsupportedKey());
    }
}

class PrivateKeyJWKTest_UnsupportedKey extends PrivateKey
{
    public function privateKeyInfo(): PrivateKeyInfo
    {
    }
    
    public function publicKey(): PublicKey
    {
    }
    
    public function toDER(): string
    {
    }
    
    public function toPEM(): PEM
    {
    }
    
    public function algorithmIdentifier(): AlgorithmIdentifierType
    {
    }
}
