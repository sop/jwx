<?php

use JWX\JWK\JWK;
use JWX\JWK\EC\ECPublicKeyJWK;
use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\EC\ECPublicKey;

/**
 * @group jwk
 * @group ec
 */
class ECPublicKeyJWKTest extends TestCase
{
    private static $_pubPEM;
    
    public static function setUpBeforeClass()
    {
        self::$_pubPEM = PEM::fromFile(
            TEST_ASSETS_DIR . "/ec/public_key_P-256.pem");
    }
    
    public static function tearDownAfterClass()
    {
        self::$_pubPEM = null;
    }
    
    public function testCreate()
    {
        $jwk = ECPublicKeyJWK::fromArray(
            array("kty" => "EC", "crv" => "", "x" => ""));
        $this->assertInstanceOf(JWK::class, $jwk);
        return $jwk;
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testCreateMissingParams()
    {
        new ECPublicKeyJWK();
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testCreateInvalidKeyType()
    {
        $params = array_fill_keys(ECPublicKeyJWK::MANAGED_PARAMS, "");
        $params["kty"] = "nope";
        ECPublicKeyJWK::fromArray($params);
    }
    
    public function testCreateFromPEM()
    {
        $jwk = ECPublicKeyJWK::fromPEM(self::$_pubPEM);
        $this->assertInstanceOf(ECPublicKeyJWK::class, $jwk);
        return $jwk;
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testCreateNoCurveFail()
    {
        $ec = new ECPublicKey("\x4\0\0");
        ECPublicKeyJWK::fromECPublicKey($ec);
    }
    
    /**
     * @depends testCreateFromPEM
     *
     * @param ECPublicKeyJWK $jwk
     */
    public function testToPEM(ECPublicKeyJWK $jwk)
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
        $ec_ref = ECPublicKey::fromPEM(self::$_pubPEM);
        $ec = ECPublicKey::fromPEM($pem);
        $this->assertEquals($ec_ref, $ec);
    }
}
