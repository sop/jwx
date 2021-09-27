<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyAlgorithm\A128GCMKWAlgorithm;
use Sop\JWX\JWE\KeyAlgorithm\AESGCMKWAlgorithm;

/**
 * @group jwe
 * @group key
 *
 * @internal
 */
class A128GCMKWTest extends TestCase
{
    public const KEY_128 = '123456789 123456';
    public const IV = '123456789 12';
    public const CEK_128 = '987654321 987654';

    public function testCreate()
    {
        $algo = new A128GCMKWAlgorithm(self::KEY_128, self::IV);
        $this->assertInstanceOf(AESGCMKWAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     */
    public function testAlgoParamValue(AESGCMKWAlgorithm $algo)
    {
        $this->assertEquals(JWA::ALGO_A128GCMKW, $algo->algorithmParamValue());
    }

    /**
     * @depends testCreate
     */
    public function testEncrypt(AESGCMKWAlgorithm $algo)
    {
        $ciphertext = $algo->encrypt(self::CEK_128, $header);
        $this->assertNotEquals(self::CEK_128, $ciphertext);
        return [$ciphertext, $header];
    }

    /**
     * @depends testCreate
     * @depends testEncrypt
     *
     * @param array $data
     */
    public function testDecrypt(AESGCMKWAlgorithm $algo, $data)
    {
        [$ciphertext, $header] = $data;
        $cek = $algo->decrypt($ciphertext, $header);
        $this->assertEquals(self::CEK_128, $cek);
    }

    public function testInvalidKeySize()
    {
        $this->expectException(\LengthException::class);
        new A128GCMKWAlgorithm('fail', self::IV);
    }
}
