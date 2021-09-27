<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\EC\ECPublicKey;
use Sop\JWX\JWK\EC\ECPublicKeyJWK;
use Sop\JWX\JWK\JWK;

/**
 * @group jwk
 * @group ec
 *
 * @internal
 */
class ECPublicKeyJWKTest extends TestCase
{
    private static $_pubPEM;

    public static function setUpBeforeClass(): void
    {
        self::$_pubPEM = PEM::fromFile(
            TEST_ASSETS_DIR . '/ec/public_key_P-256.pem');
    }

    public static function tearDownAfterClass(): void
    {
        self::$_pubPEM = null;
    }

    public function testCreate()
    {
        $jwk = ECPublicKeyJWK::fromArray(
            ['kty' => 'EC', 'crv' => '', 'x' => '']);
        $this->assertInstanceOf(JWK::class, $jwk);
        return $jwk;
    }

    public function testCreateMissingParams()
    {
        $this->expectException(\UnexpectedValueException::class);
        new ECPublicKeyJWK();
    }

    public function testCreateInvalidKeyType()
    {
        $params = array_fill_keys(ECPublicKeyJWK::MANAGED_PARAMS, '');
        $params['kty'] = 'nope';
        $this->expectException(\UnexpectedValueException::class);
        ECPublicKeyJWK::fromArray($params);
    }

    public function testCreateFromPEM()
    {
        $jwk = ECPublicKeyJWK::fromPEM(self::$_pubPEM);
        $this->assertInstanceOf(ECPublicKeyJWK::class, $jwk);
        return $jwk;
    }

    public function testCreateNoCurveFail()
    {
        $ec = new ECPublicKey("\x4\0\0");
        $this->expectException(\UnexpectedValueException::class);
        ECPublicKeyJWK::fromECPublicKey($ec);
    }

    /**
     * @depends testCreateFromPEM
     */
    public function testToPEM(ECPublicKeyJWK $jwk)
    {
        $pem = $jwk->toPEM();
        $this->assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends testToPEM
     */
    public function testRecoded(PEM $pem)
    {
        $ec_ref = ECPublicKey::fromPEM(self::$_pubPEM);
        $ec = ECPublicKey::fromPEM($pem);
        $this->assertEquals($ec_ref, $ec);
    }
}
