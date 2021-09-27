<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPublicKey;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyAlgorithm\RSAESKeyAlgorithm;
use Sop\JWX\JWE\KeyAlgorithm\RSAESPKCS1Algorithm;
use Sop\JWX\JWE\KeyManagementAlgorithm;
use Sop\JWX\JWK\RSA\RSAPrivateKeyJWK;
use Sop\JWX\JWK\RSA\RSAPublicKeyJWK;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwe
 * @group key
 *
 * @internal
 */
class RSAESKeyTest extends TestCase
{
    private static $_publicKey;

    private static $_privateKey;

    public static function setUpBeforeClass(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        self::$_privateKey = RSAPrivateKeyJWK::fromPEM($pem);
        self::$_publicKey = self::$_privateKey->publicKey();
    }

    public static function tearDownAfterClass(): void
    {
        self::$_publicKey = null;
        self::$_privateKey = null;
    }

    public function testCreate()
    {
        $algo = RSAESPKCS1Algorithm::fromPrivateKey(self::$_privateKey);
        $this->assertInstanceOf(RSAESKeyAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     */
    public function testHeaderParameters(KeyManagementAlgorithm $algo)
    {
        $params = $algo->headerParameters();
        $this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
    }

    /**
     * @depends testCreate
     */
    public function testPublicKey(RSAESKeyAlgorithm $algo)
    {
        $this->assertEquals(self::$_publicKey, $algo->publicKey());
    }

    /**
     * @depends testCreate
     */
    public function testHasPrivateKey(RSAESKeyAlgorithm $algo)
    {
        $this->assertTrue($algo->hasPrivateKey());
    }

    /**
     * @depends testCreate
     */
    public function testPrivateKey(RSAESKeyAlgorithm $algo)
    {
        $this->assertEquals(self::$_privateKey, $algo->privateKey());
    }

    public function testCreateFromPublicKey()
    {
        $algo = RSAESPKCS1Algorithm::fromPublicKey(self::$_publicKey);
        $this->assertInstanceOf(RSAESKeyAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreateFromPublicKey
     */
    public function testPrivateKeyNotSet(RSAESKeyAlgorithm $algo)
    {
        $this->expectException(\LogicException::class);
        $algo->privateKey();
    }

    public function testEncryptFail()
    {
        $jwk = RSAPublicKeyJWK::fromPEM((new RSAPublicKey(0, 0))->toPEM());
        $algo = RSAESPKCS1Algorithm::fromPublicKey($jwk);
        $this->expectException(\RuntimeException::class);
        $algo->encrypt('x');
    }

    public function testDecryptFail()
    {
        $jwk = RSAPrivateKeyJWK::fromRSAPrivateKey(
            new RSAPrivateKey(0, 0, 0, 0, 0, 0, 0, 0));
        $algo = RSAESPKCS1Algorithm::fromPrivateKey($jwk);
        $this->expectException(\RuntimeException::class);
        $algo->decrypt('x');
    }

    /**
     * @depends testCreate
     */
    public function testPubKeyFail(RSAESKeyAlgorithm $algo)
    {
        $obj = new ReflectionClass($algo);
        $prop = $obj->getProperty('_publicKey');
        $prop->setAccessible(true);
        $prop->setValue($algo, new RSAESKeyTest_PublicKeyMockup(
            ...self::$_privateKey->parameters()));
        $this->expectException(\RuntimeException::class);
        $algo->encrypt('test');
    }

    /**
     * @depends testCreate
     */
    public function testPrivKeyFail(RSAESKeyAlgorithm $algo)
    {
        $obj = new ReflectionClass($algo);
        $prop = $obj->getProperty('_privateKey');
        $prop->setAccessible(true);
        $prop->setValue($algo, new RSAESKeyTest_PrivateKeyMockup(
            ...self::$_privateKey->parameters()));
        $this->expectException(\RuntimeException::class);
        $algo->decrypt('test');
    }

    public function testFromJWKPriv()
    {
        $header = new Header(new AlgorithmParameter(JWA::ALGO_RSA1_5));
        $algo = RSAESKeyAlgorithm::fromJWK(self::$_privateKey, $header);
        $this->assertInstanceOf(RSAESPKCS1Algorithm::class, $algo);
    }

    public function testFromJWKPub()
    {
        $header = new Header(new AlgorithmParameter(JWA::ALGO_RSA1_5));
        $algo = RSAESKeyAlgorithm::fromJWK(self::$_publicKey, $header);
        $this->assertInstanceOf(RSAESPKCS1Algorithm::class, $algo);
    }

    public function testFromJWKUnsupportedAlgo()
    {
        $header = new Header(new AlgorithmParameter(JWA::ALGO_NONE));
        $this->expectException(\UnexpectedValueException::class);
        RSAESKeyAlgorithm::fromJWK(self::$_publicKey, $header);
    }
}

class RSAESKeyTest_PrivateKeyMockup extends RSAPrivateKeyJWK
{
    public function toPEM(): PEM
    {
        return new RSAESKeyTest_PEMMockup('', '');
    }
}

class RSAESKeyTest_PublicKeyMockup extends RSAPublicKeyJWK
{
    public function toPEM(): PEM
    {
        return new RSAESKeyTest_PEMMockup('', '');
    }
}

class RSAESKeyTest_PEMMockup extends PEM
{
    public function string(): string
    {
        return '';
    }
}
