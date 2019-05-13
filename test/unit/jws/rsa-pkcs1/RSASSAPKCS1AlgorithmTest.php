<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\RSA\RSAPrivateKeyJWK;
use Sop\JWX\JWS\Algorithm\RSASSAPKCS1Algorithm;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jws
 * @group rsassa
 *
 * @internal
 */
class RSASSAPKCS1AlgorithmTest extends TestCase
{
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

    public function testFromPrivateKeyJWK()
    {
        $header = new Header(new AlgorithmParameter(JWA::ALGO_RS256));
        $algo = RSASSAPKCS1Algorithm::fromJWK(self::$_privKey, $header);
        $this->assertInstanceOf(RSASSAPKCS1Algorithm::class, $algo);
        return $algo;
    }

    public function testFromPublicKeyJWK()
    {
        $header = new Header(new AlgorithmParameter(JWA::ALGO_RS256));
        $algo = RSASSAPKCS1Algorithm::fromJWK(self::$_privKey->publicKey(),
            $header);
        $this->assertInstanceOf(RSASSAPKCS1Algorithm::class, $algo);
        return $algo;
    }

    public function testFromJWKInvalidAlgo()
    {
        $header = new Header(new AlgorithmParameter(JWA::ALGO_ES256));
        $this->expectException(\UnexpectedValueException::class);
        RSASSAPKCS1Algorithm::fromJWK(self::$_privKey, $header);
    }

    public function testFromJWKInvalidKey()
    {
        $jwk = new JWK();
        $header = new Header(new AlgorithmParameter(JWA::ALGO_RS256));
        $this->expectException(\UnexpectedValueException::class);
        RSASSAPKCS1Algorithm::fromJWK($jwk, $header);
    }

    /**
     * @depends testFromPublicKeyJWK
     *
     * @param RSASSAPKCS1Algorithm $algo
     */
    public function testComputeMissingPrivateKey(RSASSAPKCS1Algorithm $algo)
    {
        $this->expectException(\LogicException::class);
        $algo->computeSignature('data');
    }

    public function testComputeFail()
    {
        $algo = RSASSAPKCS1AlgorithmTest_InvalidMethod::fromPrivateKey(
            self::$_privKey);
        $this->expectException(\RuntimeException::class);
        $algo->computeSignature('data');
    }

    public function testValidateFail()
    {
        $algo = RSASSAPKCS1AlgorithmTest_InvalidMethod::fromPrivateKey(
            self::$_privKey);
        $this->expectException(\RuntimeException::class);
        $algo->validateSignature('data', '');
    }

    /**
     * @depends testFromPrivateKeyJWK
     *
     * @param RSASSAPKCS1Algorithm $algo
     */
    public function testComputeInvalidKey(RSASSAPKCS1Algorithm $algo)
    {
        $obj = new ReflectionClass($algo);
        $prop = $obj->getProperty('_privateKey');
        $prop->setAccessible(true);
        $prop->setValue($algo, new RSASSAPKCS1AlgorithmTest_KeyMockup());
        $this->expectException(\RuntimeException::class);
        $algo->computeSignature('test');
    }

    /**
     * @depends testFromPrivateKeyJWK
     *
     * @param RSASSAPKCS1Algorithm $algo
     */
    public function testValidateInvalidKey(RSASSAPKCS1Algorithm $algo)
    {
        $obj = new ReflectionClass($algo);
        $prop = $obj->getProperty('_publicKey');
        $prop->setAccessible(true);
        $prop->setValue($algo, new RSASSAPKCS1AlgorithmTest_KeyMockup());
        $this->expectException(\RuntimeException::class);
        $algo->validateSignature('test', '');
    }

    /**
     * @depends testFromPublicKeyJWK
     *
     * @param RSASSAPKCS1Algorithm $algo
     */
    public function testHeaderParameters(RSASSAPKCS1Algorithm $algo)
    {
        $params = $algo->headerParameters();
        $this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
    }
}

class RSASSAPKCS1AlgorithmTest_InvalidMethod extends RSASSAPKCS1Algorithm
{
    public function algorithmParamValue(): string
    {
        return (string) $this->_mdMethod();
    }

    protected function _mdMethod(): int
    {
        return 0;
    }
}

class RSASSAPKCS1AlgorithmTest_KeyMockup
{
    public function toPEM()
    {
        return new RSASSAPKCS1AlgorithmTest_PEMMockup();
    }
}

class RSASSAPKCS1AlgorithmTest_PEMMockup
{
    public function string()
    {
        return '';
    }
}
