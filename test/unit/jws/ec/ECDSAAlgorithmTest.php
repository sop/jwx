<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\EC\ECPrivateKeyJWK;
use Sop\JWX\JWK\EC\ECPublicKeyJWK;
use Sop\JWX\JWK\RSA\RSAPublicKeyJWK;
use Sop\JWX\JWS\Algorithm\ECDSAAlgorithm;
use Sop\JWX\JWS\Algorithm\ES384Algorithm;
use Sop\JWX\JWS\Algorithm\ES512Algorithm;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jws
 * @group ec
 *
 * @internal
 */
class ECDSAAlgorithmTest extends TestCase
{
    private static $_jwk;

    public static function setUpBeforeClass(): void
    {
        self::$_jwk = ECPublicKeyJWK::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key_P-521.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_jwk = null;
    }

    public function testInvalidCurve()
    {
        $this->expectException(\InvalidArgumentException::class);
        ES384Algorithm::fromPublicKey(self::$_jwk);
    }

    public function testInvalidSignatureLength()
    {
        $algo = ES512Algorithm::fromPublicKey(self::$_jwk);
        $this->expectException(\UnexpectedValueException::class);
        $algo->validateSignature('test', '');
    }

    public function testHeaderParameters()
    {
        $algo = ES512Algorithm::fromPublicKey(self::$_jwk);
        $params = $algo->headerParameters();
        $this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
    }

    public function testFromPublicKeyJWK()
    {
        $header = new Header(new AlgorithmParameter(JWA::ALGO_ES512));
        $algo = ECDSAAlgorithm::fromJWK(self::$_jwk, $header);
        $this->assertInstanceOf(ES512Algorithm::class, $algo);
    }

    public function testFromPrivateKeyJWK()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key_P-521.pem');
        $jwk = ECPrivateKeyJWK::fromPEM($pem);
        $header = new Header(new AlgorithmParameter(JWA::ALGO_ES512));
        $algo = ECDSAAlgorithm::fromJWK($jwk, $header);
        $this->assertInstanceOf(ES512Algorithm::class, $algo);
    }

    public function testFromJWKUnsupportedAlgo()
    {
        $header = new Header(new AlgorithmParameter(JWA::ALGO_HS512));
        $this->expectException(\UnexpectedValueException::class);
        ECDSAAlgorithm::fromJWK(self::$_jwk, $header);
    }

    public function testFromJWKWrongType()
    {
        $jwk = RSAPublicKeyJWK::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem'));
        $header = new Header(new AlgorithmParameter(JWA::ALGO_ES256));
        $this->expectException(\UnexpectedValueException::class);
        ECDSAAlgorithm::fromJWK($jwk, $header);
    }
}
