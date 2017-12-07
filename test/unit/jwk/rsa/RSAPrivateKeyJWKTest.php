<?php

use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\JWK\RSA\RSAPublicKeyJWK;
use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;

/**
 * @group jwk
 * @group rsa
 */
class RSAPrivateKeyJWKTest extends TestCase
{
    private static $_privPEM;
    
    private static $_pubPEM;
    
    public static function setUpBeforeClass()
    {
        self::$_privPEM = PEM::fromFile(
            TEST_ASSETS_DIR . "/rsa/private_key.pem");
        self::$_pubPEM = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
    }
    
    public static function tearDownAfterClass()
    {
        self::$_privPEM = null;
        self::$_pubPEM = null;
    }
    
    public function testFromPEM()
    {
        $jwk = RSAPrivateKeyJWK::fromPEM(self::$_privPEM);
        $this->assertInstanceOf(RSAPrivateKeyJWK::class, $jwk);
        return $jwk;
    }
    
    /**
     * @depends testFromPEM
     *
     * @param RSAPrivateKeyJWK $jwk
     */
    public function testToPEM(RSAPrivateKeyJWK $jwk)
    {
        $pem = $jwk->toPEM();
        $this->assertInstanceOf(PEM::class, $pem);
        return $pem;
    }
    
    /**
     * @depends testToPEM
     *
     * @param PEM $pem
     */
    public function testRecoded(PEM $pem)
    {
        $this->assertEquals(self::$_privPEM, $pem);
    }
    
    /**
     * @depends testFromPEM
     *
     * @param RSAPrivateKeyJWK $jwk
     */
    public function testPublicKey(RSAPrivateKeyJWK $jwk)
    {
        $pk = $jwk->publicKey();
        $this->assertInstanceOf(RSAPublicKeyJWK::class, $pk);
        return $pk;
    }
    
    /**
     * @depends testPublicKey
     *
     * @param RSAPublicKeyJWK $jwk
     */
    public function testPublicKeyEquals(RSAPublicKeyJWK $jwk)
    {
        $this->assertEquals(self::$_pubPEM, $jwk->toPEM());
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testCreateMissingParameter()
    {
        new RSAPrivateKeyJWK();
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testCreateInvalidKeyType()
    {
        $params = array_fill_keys(RSAPrivateKeyJWK::MANAGED_PARAMS, "");
        $params["kty"] = "nope";
        RSAPrivateKeyJWK::fromArray($params);
    }
}
