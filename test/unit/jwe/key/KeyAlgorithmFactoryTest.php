<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyAlgorithm\KeyAlgorithmFactory;
use Sop\JWX\JWE\KeyManagementAlgorithm;
use Sop\JWX\JWK\JWKSet;
use Sop\JWX\JWK\Parameter\KeyIDParameter as JWKID;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;
use Sop\JWX\JWT\Parameter\KeyIDParameter;

/**
 * @group jwe
 * @group key
 *
 * @internal
 */
class KeyAlgorithmFactoryTest extends TestCase
{
    public const KEY_ID = 'test-key';

    private static $_header;

    public static function setUpBeforeClass(): void
    {
        self::$_header = new Header(new AlgorithmParameter(JWA::ALGO_DIR),
            new KeyIDParameter(self::KEY_ID));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_header = null;
    }

    public function testAlgoByKey()
    {
        $jwk = SymmetricKeyJWK::fromKey('test');
        $factory = new KeyAlgorithmFactory(self::$_header);
        $algo = $factory->algoByKey($jwk);
        $this->assertInstanceOf(KeyManagementAlgorithm::class, $algo);
    }

    public function testAlgoByKeyUnsupportedFail()
    {
        $header = new Header(new AlgorithmParameter(JWA::ALGO_HS256));
        $jwk = SymmetricKeyJWK::fromKey('test');
        $factory = new KeyAlgorithmFactory($header);
        $this->expectException(\UnexpectedValueException::class);
        $factory->algoByKey($jwk);
    }

    public function testAlgoByKeys()
    {
        $jwk = SymmetricKeyJWK::fromKey('test', new JWKID(self::KEY_ID));
        $factory = new KeyAlgorithmFactory(self::$_header);
        $algo = $factory->algoByKeys(new JWKSet($jwk));
        $this->assertInstanceOf(KeyManagementAlgorithm::class, $algo);
    }

    public function testAlgoByKeysNoKeyIDParam()
    {
        $header = new Header(new AlgorithmParameter(JWA::ALGO_DIR));
        $jwk = SymmetricKeyJWK::fromKey('test', new JWKID(self::KEY_ID));
        $factory = new KeyAlgorithmFactory($header);
        $this->expectException(\UnexpectedValueException::class);
        $factory->algoByKeys(new JWKSet($jwk));
    }

    public function testAlgoByKeysNoKey()
    {
        $header = new Header(new AlgorithmParameter(JWA::ALGO_DIR),
            new KeyIDParameter('fail'));
        $jwk = SymmetricKeyJWK::fromKey('test', new JWKID(self::KEY_ID));
        $factory = new KeyAlgorithmFactory($header);
        $this->expectException(\UnexpectedValueException::class);
        $factory->algoByKeys(new JWKSet($jwk));
    }
}
