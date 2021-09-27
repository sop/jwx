<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWE\ContentEncryptionAlgorithm;
use Sop\JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use Sop\JWX\JWE\EncryptionAlgorithm\AESCBCAlgorithm;
use Sop\JWX\JWE\Exception\AuthenticationException;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwe
 * @group encryption
 *
 * @internal
 */
class AESCBCEncryptionTest extends TestCase
{
    public const KEY_128 = '123456789 123456789 123456789 12';
    public const IV = '123456789 123456';

    public function testCreate()
    {
        $algo = new A128CBCHS256Algorithm();
        $this->assertInstanceOf(AESCBCAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     */
    public function testIVSize(ContentEncryptionAlgorithm $algo)
    {
        $this->assertEquals(16, $algo->ivSize());
    }

    /**
     * @depends testCreate
     */
    public function testHeaderParams(ContentEncryptionAlgorithm $algo)
    {
        $params = $algo->headerParameters();
        $this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
    }

    /**
     * @depends testCreate
     */
    public function testInvalidKeySize(ContentEncryptionAlgorithm $algo)
    {
        $this->expectException(\RuntimeException::class);
        $algo->encrypt('test', '1234', self::IV, '');
    }

    /**
     * @depends testCreate
     */
    public function testInvalidIVSize(ContentEncryptionAlgorithm $algo)
    {
        $this->expectException(\RuntimeException::class);
        $algo->encrypt('test', self::KEY_128, '1234', '');
    }

    /**
     * @depends testCreate
     */
    public function testAuthFail(ContentEncryptionAlgorithm $algo)
    {
        static $data = 'test';
        [$ciphertext, $auth_tag] = $algo->encrypt($data, self::KEY_128, self::IV, '');
        $this->expectException(AuthenticationException::class);
        $algo->decrypt($ciphertext, self::KEY_128, self::IV, '', strrev($auth_tag));
    }

    public function testUnsupportedCipher()
    {
        $algo = new AESCBCEncryptionTest_UnsupportedCipher();
        $this->expectException(\RuntimeException::class);
        $algo->encrypt('test', self::KEY_128, self::IV, '');
    }

    /**
     * @depends testCreate
     */
    public function testDecryptFail(AESCBCAlgorithm $algo)
    {
        static $ciphertext = "\0";
        static $aad = '';
        $cls = new ReflectionClass($algo);
        $mtd_computeAuthTag = $cls->getMethod('_computeAuthTag');
        $mtd_computeAuthTag->setAccessible(true);
        $mtd_aadLen = $cls->getMethod('_aadLen');
        $mtd_aadLen->setAccessible(true);
        $auth_data = $aad . self::IV . $ciphertext . $mtd_aadLen->invoke($algo, $aad);
        $auth_tag = $mtd_computeAuthTag->invoke($algo, $auth_data, self::KEY_128);
        $this->expectException(\RuntimeException::class);
        $algo->decrypt($ciphertext, self::KEY_128, self::IV, $aad, $auth_tag);
    }
}

class AESCBCEncryptionTest_UnsupportedCipher extends A128CBCHS256Algorithm
{
    protected function _cipherMethod(): string
    {
        return 'nope';
    }
}
