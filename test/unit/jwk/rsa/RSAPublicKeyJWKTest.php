<?php

use JWX\JWK\RSA\RSAPublicKeyJWK;
use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;

/**
 * @group jwk
 * @group rsa
 */
class RSAPublicKeyJWKTest extends TestCase
{
    private static $_pubPEM;
    
    public static function setUpBeforeClass()
    {
        self::$_pubPEM = PEM::fromFile(TEST_ASSETS_DIR . "/rsa/public_key.pem");
    }
    
    public static function tearDownAfterClass()
    {
        self::$_pubPEM = null;
    }
    
    public function testFromPEM()
    {
        $jwk = RSAPublicKeyJWK::fromPEM(self::$_pubPEM);
        $this->assertInstanceOf(RSAPublicKeyJWK::class, $jwk);
        return $jwk;
    }
    
    /**
     * @depends testFromPEM
     *
     * @param RSAPublicKeyJWK $jwk
     */
    public function testToPEM(RSAPublicKeyJWK $jwk)
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
        $this->assertEquals(self::$_pubPEM, $pem);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testCreateMissingParameter()
    {
        new RSAPublicKeyJWK();
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testCreateInvalidKeyType()
    {
        $params = array_fill_keys(RSAPublicKeyJWK::MANAGED_PARAMS, "");
        $params["kty"] = "nope";
        RSAPublicKeyJWK::fromArray($params);
    }
}
