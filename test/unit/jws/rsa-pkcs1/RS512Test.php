<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\RSA\RSAPrivateKeyJWK;
use Sop\JWX\JWS\Algorithm\RS512Algorithm;
use Sop\JWX\JWS\Algorithm\RSASSAPKCS1Algorithm;
use Sop\JWX\JWS\SignatureAlgorithm;
use Sop\JWX\JWT\Parameter\AlgorithmParameterValue;

/**
 * @group jws
 * @group rsassa
 *
 * @internal
 */
class RS512Test extends TestCase
{
    public const DATA = 'CONTENT';

    private static $_privKey;

    public static function setUpBeforeClass(): void
    {
        self::$_privKey = RSAPrivateKeyJWK::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_privKey = null;
    }

    public function testCreate()
    {
        $algo = RS512Algorithm::fromPrivateKey(self::$_privKey);
        $this->assertInstanceOf(RSASSAPKCS1Algorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     */
    public function testAlgoParamValue(AlgorithmParameterValue $algo)
    {
        $this->assertEquals(JWA::ALGO_RS512, $algo->algorithmParamValue());
    }

    /**
     * @depends testCreate
     */
    public function testSign(SignatureAlgorithm $algo)
    {
        $sig = $algo->computeSignature(self::DATA);
        $this->assertIsString($sig);
        return $sig;
    }

    /**
     * @depends testCreate
     * @depends testSign
     *
     * @param string $signature
     */
    public function testValidate(SignatureAlgorithm $algo, $signature)
    {
        $this->assertTrue($algo->validateSignature(self::DATA, $signature));
    }
}
