<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\ContentEncryptionAlgorithm;
use Sop\JWX\JWE\EncryptionAlgorithm\A192GCMAlgorithm;
use Sop\JWX\JWE\EncryptionAlgorithm\AESGCMAlgorithm;

/**
 * @group jwe
 * @group encryption
 *
 * @internal
 */
class A192GCMEncryptionTest extends TestCase
{
    const PLAINTEXT = 'My hovercraft is full of eels.';
    const KEY = '0123456789abcdef01234567';
    const IV = '0123456789ab';
    const AAD = 'I will not buy this record, it is scratched.';

    public function testCreate()
    {
        $algo = new A192GCMAlgorithm();
        $this->assertInstanceOf(ContentEncryptionAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     *
     * @param ContentEncryptionAlgorithm $algo
     */
    public function testKeySize(AESGCMAlgorithm $algo)
    {
        $this->assertEquals(24, $algo->keySize());
    }

    /**
     * @depends testCreate
     *
     * @param ContentEncryptionAlgorithm $algo
     */
    public function testAlgoParamValue(ContentEncryptionAlgorithm $algo)
    {
        $this->assertEquals(JWA::ALGO_A192GCM,
            $algo->encryptionAlgorithmParamValue());
    }

    /**
     * @depends testCreate
     *
     * @param ContentEncryptionAlgorithm $algo
     */
    public function testEncrypt(ContentEncryptionAlgorithm $algo)
    {
        [$ciphertext, $auth_tag] = $algo->encrypt(self::PLAINTEXT, self::KEY,
            self::IV, self::AAD);
        $this->assertNotEquals(self::PLAINTEXT, $ciphertext);
        return [$ciphertext, $auth_tag];
    }

    /**
     * @depends testCreate
     * @depends testEncrypt
     *
     * @param array $data
     */
    public function testDecrypt(ContentEncryptionAlgorithm $algo, array $data)
    {
        $plaintext = $algo->decrypt($data[0], self::KEY, self::IV, self::AAD, $data[1]);
        $this->assertEquals(self::PLAINTEXT, $plaintext);
    }
}
