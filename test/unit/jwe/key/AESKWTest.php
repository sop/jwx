<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyAlgorithm\A128KWAlgorithm;
use Sop\JWX\JWE\KeyAlgorithm\AESKWAlgorithm;
use Sop\JWX\JWE\KeyManagementAlgorithm;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\Parameter\AlgorithmParameter;
use Sop\JWX\JWK\Parameter\KeyTypeParameter;
use Sop\JWX\JWK\Parameter\KeyValueParameter;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwe
 * @group key
 *
 * @internal
 */
class AESKWTest extends TestCase
{
    const KEY_128 = '123456789 123456';

    public function testCreate()
    {
        $algo = new A128KWAlgorithm(self::KEY_128);
        $this->assertInstanceOf(AESKWAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     *
     * @param KeyManagementAlgorithm $algo
     */
    public function testHeaderParameters(KeyManagementAlgorithm $algo)
    {
        $params = $algo->headerParameters();
        $this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
    }

    /**
     * @depends testCreate
     *
     * @param KeyManagementAlgorithm $algo
     */
    public function testCEKForEncryption(KeyManagementAlgorithm $algo)
    {
        $cek = $algo->cekForEncryption(16);
        $this->assertEquals(16, strlen($cek));
    }

    /**
     * @depends testCreate
     * @requires PHP < 8
     *
     * @param KeyManagementAlgorithm $algo
     */
    public function testCEKForEncryptionFail(KeyManagementAlgorithm $algo)
    {
        $this->expectException(\InvalidArgumentException::class);
        $algo->cekForEncryption(0);
    }
    
    /**
     * @depends testCreate
     * @requires PHP >= 8
     *
     * @param KeyManagementAlgorithm $algo
     */
    public function testCEKForEncryptionFailPhp8(KeyManagementAlgorithm $algo)
    {
        $this->expectException(\ValueError::class);
        $algo->cekForEncryption(0);
    }

    public function testFromJWK()
    {
        $jwk = new JWK(new AlgorithmParameter(JWA::ALGO_A128KW),
            new KeyTypeParameter(KeyTypeParameter::TYPE_OCT),
            KeyValueParameter::fromString(self::KEY_128));
        $header = new Header();
        $algo = AESKWAlgorithm::fromJWK($jwk, $header);
        $this->assertInstanceOf(AESKWAlgorithm::class, $algo);
    }

    public function testFromJWKNoAlgo()
    {
        $jwk = new JWK(new KeyTypeParameter(KeyTypeParameter::TYPE_OCT),
            KeyValueParameter::fromString(self::KEY_128));
        $header = new Header();
        $this->expectException(\UnexpectedValueException::class);
        AESKWAlgorithm::fromJWK($jwk, $header);
    }

    public function testFromJWKUnsupportedAlgo()
    {
        $jwk = new JWK(new AlgorithmParameter(JWA::ALGO_NONE),
            new KeyTypeParameter(KeyTypeParameter::TYPE_OCT),
            KeyValueParameter::fromString(self::KEY_128));
        $header = new Header();
        $this->expectException(\UnexpectedValueException::class);
        AESKWAlgorithm::fromJWK($jwk, $header);
    }
}
