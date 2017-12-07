<?php

use JWX\JWA\JWA;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\JWTParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwe
 * @group key
 */
class DirectCEKTest extends TestCase
{
    const KEY_128 = "123456789 123456";
    
    public function testCreate()
    {
        $algo = new DirectCEKAlgorithm(self::KEY_128);
        $this->assertInstanceOf(DirectCEKAlgorithm::class, $algo);
        return $algo;
    }
    
    /**
     * @depends testCreate
     *
     * @param DirectCEKAlgorithm $algo
     */
    public function testCEK(DirectCEKAlgorithm $algo)
    {
        $this->assertEquals(self::KEY_128, $algo->cek());
    }
    
    /**
     * @depends testCreate
     *
     * @param DirectCEKAlgorithm $algo
     */
    public function testAlgoValue(DirectCEKAlgorithm $algo)
    {
        $this->assertEquals(JWA::ALGO_DIR, $algo->algorithmParamValue());
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
     * @param DirectCEKAlgorithm $algo
     */
    public function testEncrypt(DirectCEKAlgorithm $algo)
    {
        $data = $algo->encrypt(self::KEY_128);
        $this->assertEquals("", $data);
        return $data;
    }
    
    /**
     * @depends testCreate
     * @depends testEncrypt
     *
     * @param DirectCEKAlgorithm $algo
     */
    public function testDecrypt(DirectCEKAlgorithm $algo, $data)
    {
        $cek = $algo->decrypt($data);
        $this->assertEquals(self::KEY_128, $cek);
    }
    
    /**
     * @depends testCreate
     * @expectedException LogicException
     *
     * @param DirectCEKAlgorithm $algo
     */
    public function testEncryptFail(DirectCEKAlgorithm $algo)
    {
        $algo->encrypt("fail");
    }
    
    /**
     * @depends testCreate
     * @expectedException UnexpectedValueException
     *
     * @param DirectCEKAlgorithm $algo
     */
    public function testDecryptFail(DirectCEKAlgorithm $algo)
    {
        $algo->decrypt("x");
    }
    
    /**
     * @depends testCreate
     *
     * @param DirectCEKAlgorithm $algo
     */
    public function testCEKForEncryption(DirectCEKAlgorithm $algo)
    {
        $cek = $algo->cekForEncryption(strlen(self::KEY_128));
        $this->assertEquals(self::KEY_128, $cek);
    }
    
    /**
     * @depends testCreate
     * @expectedException UnexpectedValueException
     *
     * @param DirectCEKAlgorithm $algo
     */
    public function testCEKForEncryptionFail(DirectCEKAlgorithm $algo)
    {
        $algo->cekForEncryption(1);
    }
    
    public function testFromJWK()
    {
        $jwk = SymmetricKeyJWK::fromKey(self::KEY_128);
        $header = new Header(new AlgorithmParameter(JWA::ALGO_DIR));
        $algo = DirectCEKAlgorithm::fromJWK($jwk, $header);
        $this->assertInstanceOf(DirectCEKAlgorithm::class, $algo);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testFromJWKInvalidAlgo()
    {
        $jwk = SymmetricKeyJWK::fromKey(self::KEY_128);
        $header = new Header(new AlgorithmParameter(JWA::ALGO_A128KW));
        DirectCEKAlgorithm::fromJWK($jwk, $header);
    }
}
