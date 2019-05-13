<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWE\ContentEncryptionAlgorithm;
use Sop\JWX\JWE\EncryptionAlgorithm\A128GCMAlgorithm;
use Sop\JWX\JWE\EncryptionAlgorithm\AESGCMAlgorithm;
use Sop\JWX\JWE\Exception\AuthenticationException;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwe
 * @group encryption
 *
 * @internal
 */
class AESGCMEncryptionTest extends TestCase
{
    const KEY = '0123456789abcdef';
    const IV = '0123456789ab';

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
     *
     * @param ContentEncryptionAlgorithm $algo
     */
    public function testInvalidKeySize(ContentEncryptionAlgorithm $algo)
    {
        $this->expectException(\RuntimeException::class);
        $algo->encrypt('test', '1234', self::IV, '');
    }

    /**
     * @depends testCreate
     *
     * @param ContentEncryptionAlgorithm $algo
     */
    public function testInvalidIVSize(ContentEncryptionAlgorithm $algo)
    {
        $this->expectException(\RuntimeException::class);
        $algo->encrypt('test', self::KEY, '1234', '');
    }

    /**
     * @depends testCreate
     *
     * @param ContentEncryptionAlgorithm $algo
     */
    public function testAuthFail(ContentEncryptionAlgorithm $algo)
    {
        static $data = 'test';
        [$ciphertext, $auth_tag] = $algo->encrypt($data, self::KEY, self::IV, '');
        $this->expectException(AuthenticationException::class);
        $algo->decrypt($ciphertext, self::KEY, self::IV, '', strrev($auth_tag));
    }
}
