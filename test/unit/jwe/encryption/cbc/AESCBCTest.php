<?php

use JWX\JWE\ContentEncryptionAlgorithm;
use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\EncryptionAlgorithm\AESCBCAlgorithm;
use JWX\JWT\Parameter\JWTParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwe
 * @group encryption
 */
class AESCBCEncryptionTest extends TestCase
{
    const KEY_128 = "123456789 123456789 123456789 12";
    const IV = "123456789 123456";
    
    public function testCreate()
    {
        $algo = new A128CBCHS256Algorithm();
        $this->assertInstanceOf(AESCBCAlgorithm::class, $algo);
        return $algo;
    }
    
    /**
     * @depends testCreate
     *
     * @param ContentEncryptionAlgorithm $algo
     */
    public function testIVSize(ContentEncryptionAlgorithm $algo)
    {
        $this->assertEquals(16, $algo->ivSize());
    }
    
    /**
     * @depends testCreate
     *
     * @param ContentEncryptionAlgorithm $algo
     */
    public function testHeaderParams(ContentEncryptionAlgorithm $algo)
    {
        $params = $algo->headerParameters();
        $this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
    }
    
    /**
     * @depends testCreate
     * @expectedException RuntimeException
     *
     * @param ContentEncryptionAlgorithm $algo
     */
    public function testInvalidKeySize(ContentEncryptionAlgorithm $algo)
    {
        $algo->encrypt("test", "1234", self::IV, "");
    }
    
    /**
     * @depends testCreate
     * @expectedException RuntimeException
     *
     * @param ContentEncryptionAlgorithm $algo
     */
    public function testInvalidIVSize(ContentEncryptionAlgorithm $algo)
    {
        $algo->encrypt("test", self::KEY_128, "1234", "");
    }
    
    /**
     * @depends testCreate
     * @expectedException JWX\JWE\Exception\AuthenticationException
     *
     * @param ContentEncryptionAlgorithm $algo
     */
    public function testAuthFail(ContentEncryptionAlgorithm $algo)
    {
        static $data = "test";
        list($ciphertext, $auth_tag) = $algo->encrypt($data, self::KEY_128,
            self::IV, "");
        $algo->decrypt($ciphertext, self::KEY_128, self::IV, "",
            strrev($auth_tag));
    }
    
    /**
     * @expectedException RuntimeException
     */
    public function testUnsupportedCipher()
    {
        $algo = new AESCBCEncryptionTest_UnsupportedCipher();
        $algo->encrypt("test", self::KEY_128, self::IV, "");
    }
    
    /**
     * @depends testCreate
     * @expectedException RuntimeException
     *
     * @param AESCBCAlgorithm $algo
     */
    public function testDecryptFail(AESCBCAlgorithm $algo)
    {
        static $ciphertext = "\0";
        static $aad = "";
        $cls = new ReflectionClass($algo);
        $mtd_computeAuthTag = $cls->getMethod("_computeAuthTag");
        $mtd_computeAuthTag->setAccessible(true);
        $mtd_aadLen = $cls->getMethod("_aadLen");
        $mtd_aadLen->setAccessible(true);
        $auth_data = $aad . self::IV . $ciphertext .
             $mtd_aadLen->invoke($algo, $aad);
        $auth_tag = $mtd_computeAuthTag->invoke($algo, $auth_data, self::KEY_128);
        $algo->decrypt($ciphertext, self::KEY_128, self::IV, $aad, $auth_tag);
    }
}

class AESCBCEncryptionTest_UnsupportedCipher extends A128CBCHS256Algorithm
{
    protected function _cipherMethod(): string
    {
        return "nope";
    }
}
