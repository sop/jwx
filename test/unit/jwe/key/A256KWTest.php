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
    const KEY_256 = '123456789 123456789 123456789 12';
    const CEK_256 = '987654321 987654321 987654321 98';

    public function testCreate()
    {
        $algo = new A256KWAlgorithm(self::KEY_256);
        $this->assertInstanceOf(AESKWAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     *
     * @param AESKWAlgorithm $algo
     */
    public function testAlgoParamValue(AESKWAlgorithm $algo)
    {
        $this->assertEquals(JWA::ALGO_A256KW, $algo->algorithmParamValue());
    }

    /**
     * @depends testCreate
     *
     * @param AESKWAlgorithm $algo
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
     * @param AESKWAlgorithm $algo
     * @param string         $data
     */
    public function testDecrypt(AESKWAlgorithm $algo, $data)
    {
        $cek = $algo->decrypt($data);
        $this->assertEquals(self::CEK_256, $cek);
    }
}
