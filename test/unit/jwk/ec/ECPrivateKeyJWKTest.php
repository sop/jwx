<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\EC\ECPrivateKey;
use Sop\JWX\JWK\EC\ECPrivateKeyJWK;
use Sop\JWX\JWK\EC\ECPublicKeyJWK;
use Sop\JWX\JWK\JWK;

/**
 * @group jwk
 * @group ec
 *
 * @internal
 */
class ECPrivateKeyJWKTest extends TestCase
{
    private static $_privPEM;

    private static $_pubPEM;

    public static function setUpBeforeClass(): void
    {
        self::$_privPEM = PEM::fromFile(
            TEST_ASSETS_DIR . '/ec/private_key_P-256.pem');
        self::$_pubPEM = PEM::fromFile(
            TEST_ASSETS_DIR . '/ec/public_key_P-256.pem');
    }

    public static function tearDownAfterClass(): void
    {
        self::$_privPEM = null;
        self::$_pubPEM = null;
    }

    public function testCreate()
    {
        $jwk = ECPrivateKeyJWK::fromArray(
            ['kty' => 'EC', 'crv' => '', 'x' => '', 'd' => '']);
        $this->assertInstanceOf(JWK::class, $jwk);
        return $jwk;
    }

    public function testCreateMissingParams()
    {
        $this->expectException(\UnexpectedValueException::class);
        new ECPrivateKeyJWK();
    }

    public function testCreateInvalidKeyType()
    {
        $params = array_fill_keys(ECPrivateKeyJWK::MANAGED_PARAMS, '');
        $params['kty'] = 'nope';
        $this->expectException(\UnexpectedValueException::class);
        ECPrivateKeyJWK::fromArray($params);
    }

    public function testCreateFromPEM()
    {
        $jwk = ECPrivateKeyJWK::fromPEM(self::$_privPEM);
        $this->assertInstanceOf(ECPrivateKeyJWK::class, $jwk);
        return $jwk;
    }

    public function testCreateNoCurveFail()
    {
        $ec = new ECPrivateKey("\0");
        $this->expectException(\UnexpectedValueException::class);
        ECPrivateKeyJWK::fromECPrivateKey($ec);
    }

    /**
     * @depends testCreateFromPEM
     *
     * @param ECPrivateKeyJWK $jwk
     */
    public function testGetPublicKey(ECPrivateKeyJWK $jwk)
    {
        $pub = $jwk->publicKey();
        $this->assertInstanceOf(ECPublicKeyJWK::class, $pub);
        return $pub;
    }

    /**
     * @depends testCreateFromPEM
     *
     * @param ECPrivateKeyJWK $jwk
     */
    public function testToPEM(ECPrivateKeyJWK $jwk)
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
        $ec_ref = ECPrivateKey::fromPEM(self::$_privPEM);
        $ec = ECPrivateKey::fromPEM($pem);
        $this->assertEquals($ec_ref, $ec);
    }
}
