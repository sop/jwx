<?php

use JWX\JWA\JWA;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWE\KeyAlgorithm\A128KWAlgorithm;
use JWX\JWE\KeyAlgorithm\AESKWAlgorithm;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\AlgorithmParameter;
use JWX\JWK\Parameter\KeyTypeParameter;
use JWX\JWK\Parameter\KeyValueParameter;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\JWTParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwe
 * @group key
 */
class AESKWTest extends TestCase
{
    const KEY_128 = "123456789 123456";
    
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
     * @expectedException RuntimeException
     *
     * @param KeyManagementAlgorithm $algo
     */
    public function testCEKForEncryptionFail(KeyManagementAlgorithm $algo)
    {
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
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testFromJWKNoAlgo()
    {
        $jwk = new JWK(new KeyTypeParameter(KeyTypeParameter::TYPE_OCT),
            KeyValueParameter::fromString(self::KEY_128));
        $header = new Header();
        AESKWAlgorithm::fromJWK($jwk, $header);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testFromJWKUnsupportedAlgo()
    {
        $jwk = new JWK(new AlgorithmParameter(JWA::ALGO_NONE),
            new KeyTypeParameter(KeyTypeParameter::TYPE_OCT),
            KeyValueParameter::fromString(self::KEY_128));
        $header = new Header();
        AESKWAlgorithm::fromJWK($jwk, $header);
    }
}
