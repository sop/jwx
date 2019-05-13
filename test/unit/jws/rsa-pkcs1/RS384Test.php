<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\RSA\RSAPrivateKeyJWK;
use Sop\JWX\JWS\Algorithm\RS384Algorithm;
use Sop\JWX\JWS\Algorithm\RSASSAPKCS1Algorithm;
use Sop\JWX\JWS\SignatureAlgorithm;
use Sop\JWX\JWT\Parameter\AlgorithmParameterValue;

/**
 * @group jws
 * @group rsassa
 *
 * @internal
 */
class RS384Test extends TestCase
{
    const DATA = 'CONTENT';

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
        $algo = RS384Algorithm::fromPrivateKey(self::$_privKey);
        $this->assertInstanceOf(RSASSAPKCS1Algorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     *
     * @param AlgorithmParameterValue $algo
     */
    public function testAlgoParamValue(AlgorithmParameterValue $algo)
    {
        $this->assertEquals(JWA::ALGO_RS384, $algo->algorithmParamValue());
    }

    /**
     * @depends testCreate
     *
     * @param SignatureAlgorithm $algo
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
     * @param SignatureAlgorithm $algo
     * @param string             $signature
     */
    public function testValidate(SignatureAlgorithm $algo, $signature)
    {
        $this->assertTrue($algo->validateSignature(self::DATA, $signature));
    }
}
