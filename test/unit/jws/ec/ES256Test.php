<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\EC\ECPrivateKeyJWK;
use Sop\JWX\JWS\Algorithm\ECDSAAlgorithm;
use Sop\JWX\JWS\Algorithm\ES256Algorithm;
use Sop\JWX\JWS\SignatureAlgorithm;
use Sop\JWX\JWT\Parameter\AlgorithmParameterValue;

/**
 * @group jws
 * @group ec
 *
 * @internal
 */
class ES256Test extends TestCase
{
    public const DATA = 'CONTENT';

    private static $_jwk;

    public static function setUpBeforeClass(): void
    {
        self::$_jwk = ECPrivateKeyJWK::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key_P-256.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_jwk = null;
    }

    public function testCreate()
    {
        $algo = ES256Algorithm::fromPrivateKey(self::$_jwk);
        $this->assertInstanceOf(ECDSAAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     */
    public function testAlgoParamValue(AlgorithmParameterValue $algo)
    {
        $this->assertEquals(JWA::ALGO_ES256, $algo->algorithmParamValue());
    }

    /**
     * @depends testCreate
     */
    public function testSign(SignatureAlgorithm $algo)
    {
        $sig = $algo->computeSignature(self::DATA);
        $this->assertEquals(64, strlen($sig));
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
