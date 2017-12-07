<?php

use JWX\JWE\ContentEncryptionAlgorithm;
use JWX\JWE\EncryptionAlgorithm\A128GCMAlgorithm;
use JWX\JWE\EncryptionAlgorithm\AESGCMAlgorithm;
use JWX\JWT\Parameter\JWTParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwe
 * @group encryption
 */
class AESGCMEncryptionTest extends TestCase
{
    const KEY = "0123456789abcdef";
    const IV = "0123456789ab";
    
    public function testCreate()
    {
        $algo = new A128GCMAlgorithm();
        $this->assertInstanceOf(AESGCMAlgorithm::class, $algo);
        return $algo;
    }
    
    /**
     * @depends testCreate
     *
     * @param ContentEncryptionAlgorithm $algo
     */
    public function testIVSize(ContentEncryptionAlgorithm $algo)
    {
        $this->assertEquals(12, $algo->ivSize());
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
        $algo->encrypt("test", self::KEY, "1234", "");
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
        list($ciphertext, $auth_tag) = $algo->encrypt($data, self::KEY, self::IV,
            "");
        $algo->decrypt($ciphertext, self::KEY, self::IV, "", strrev($auth_tag));
    }
}
