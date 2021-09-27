<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\JWX\JWK\RSA\RSAPrivateKeyJWK;
use Sop\JWX\JWK\RSA\RSAPublicKeyJWK;

/**
 * @group jwk
 * @group rsa
 *
 * @internal
 */
class RSAPrivateKeyJWKTest extends TestCase
{
    private static $_privPEM;

    private static $_pubPEM;

    public static function setUpBeforeClass(): void
    {
        self::$_privPEM = PEM::fromFile(
            TEST_ASSETS_DIR . '/rsa/private_key.pem');
        self::$_pubPEM = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
    }

    public static function tearDownAfterClass(): void
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
     */
    public function testToPEM(RSAPrivateKeyJWK $jwk)
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
        $this->assertEquals(self::$_privPEM, $pem);
    }

    /**
     * @depends testFromPEM
     */
    public function testPublicKey(RSAPrivateKeyJWK $jwk)
    {
        $pk = $jwk->publicKey();
        $this->assertInstanceOf(RSAPublicKeyJWK::class, $pk);
        return $pk;
    }

    /**
     * @depends testPublicKey
     */
    public function testPublicKeyEquals(RSAPublicKeyJWK $jwk)
    {
        $this->assertEquals(self::$_pubPEM, $jwk->toPEM());
    }

    public function testCreateMissingParameter()
    {
        $this->expectException(\UnexpectedValueException::class);
        new RSAPrivateKeyJWK();
    }

    public function testCreateInvalidKeyType()
    {
        $params = array_fill_keys(RSAPrivateKeyJWK::MANAGED_PARAMS, '');
        $params['kty'] = 'nope';
        $this->expectException(\UnexpectedValueException::class);
        RSAPrivateKeyJWK::fromArray($params);
    }
}
