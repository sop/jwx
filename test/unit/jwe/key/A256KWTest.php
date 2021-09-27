<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyAlgorithm\A256KWAlgorithm;
use Sop\JWX\JWE\KeyAlgorithm\AESKWAlgorithm;

/**
 * @group jwe
 * @group key
 *
 * @internal
 */
class A256KWTest extends TestCase
{
    public const KEY_256 = '123456789 123456789 123456789 12';
    public const CEK_256 = '987654321 987654321 987654321 98';

    public function testCreate()
    {
        $algo = new A256KWAlgorithm(self::KEY_256);
        $this->assertInstanceOf(AESKWAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     */
    public function testAlgoParamValue(AESKWAlgorithm $algo)
    {
        $this->assertEquals(JWA::ALGO_A256KW, $algo->algorithmParamValue());
    }

    /**
     * @depends testCreate
     */
    public function testEncrypt(AESKWAlgorithm $algo)
    {
        $data = $algo->encrypt(self::CEK_256);
        $this->assertNotEquals(self::CEK_256, $data);
        return $data;
    }

    /**
     * @depends testCreate
     * @depends testEncrypt
     *
     * @param string $data
     */
    public function testDecrypt(AESKWAlgorithm $algo, $data)
    {
        $cek = $algo->decrypt($data);
        $this->assertEquals(self::CEK_256, $cek);
    }
}
