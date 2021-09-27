<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\JWX\JWK\RSA\RSAPublicKeyJWK;

/**
 * @group jwk
 * @group rsa
 *
 * @internal
 */
class RSAPublicKeyJWKTest extends TestCase
{
    private static $_pubPEM;

    public static function setUpBeforeClass(): void
    {
        self::$_pubPEM = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
    }

    public static function tearDownAfterClass(): void
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
     */
    public function testToPEM(RSAPublicKeyJWK $jwk)
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
        $this->assertEquals(self::$_pubPEM, $pem);
    }

    public function testCreateMissingParameter()
    {
        $this->expectException(\UnexpectedValueException::class);
        new RSAPublicKeyJWK();
    }

    public function testCreateInvalidKeyType()
    {
        $params = array_fill_keys(RSAPublicKeyJWK::MANAGED_PARAMS, '');
        $params['kty'] = 'nope';
        $this->expectException(\UnexpectedValueException::class);
        RSAPublicKeyJWK::fromArray($params);
    }
}
