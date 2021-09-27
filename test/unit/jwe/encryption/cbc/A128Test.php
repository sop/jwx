<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\ContentEncryptionAlgorithm;
use Sop\JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use Sop\JWX\JWE\EncryptionAlgorithm\AESCBCAlgorithm;

/**
 * @group jwe
 * @group encryption
 *
 * @internal
 */
class A128CBCEncryptionTest extends TestCase
{
    public const PLAINTEXT = 'My hovercraft is full of eels.';
    public const KEY_128 = '123456789 123456789 123456789 12';
    public const IV = '123456789 123456';
    public const AAD = 'I will not buy this record, it is scratched.';

    public function testCreate()
    {
        $algo = new A128CBCHS256Algorithm();
        $this->assertInstanceOf(ContentEncryptionAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     *
     * @param ContentEncryptionAlgorithm $algo
     */
    public function testKeySize(AESCBCAlgorithm $algo)
    {
        $this->assertEquals(32, $algo->keySize());
    }

    /**
     * @depends testCreate
     */
    public function testAlgoParamValue(ContentEncryptionAlgorithm $algo)
    {
        $this->assertEquals(JWA::ALGO_A128CBC_HS256,
            $algo->encryptionAlgorithmParamValue());
    }

    /**
     * @depends testCreate
     */
    public function testEncrypt(ContentEncryptionAlgorithm $algo)
    {
        [$ciphertext, $auth_tag] = $algo->encrypt(self::PLAINTEXT,
            self::KEY_128, self::IV, self::AAD);
        $this->assertNotEquals(self::PLAINTEXT, $ciphertext);
        return [$ciphertext, $auth_tag];
    }

    /**
     * @depends testCreate
     * @depends testEncrypt
     */
    public function testDecrypt(ContentEncryptionAlgorithm $algo, array $data)
    {
        $plaintext = $algo->decrypt($data[0], self::KEY_128, self::IV, self::AAD, $data[1]);
        $this->assertEquals(self::PLAINTEXT, $plaintext);
    }
}
