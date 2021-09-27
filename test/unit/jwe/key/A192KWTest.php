<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyAlgorithm\A192KWAlgorithm;
use Sop\JWX\JWE\KeyAlgorithm\AESKWAlgorithm;

/**
 * @group jwe
 * @group key
 *
 * @internal
 */
class A192KWTest extends TestCase
{
    public const KEY_192 = '123456789 123456789 1234';
    public const CEK_192 = '987654321 987654321 9876';

    public function testCreate()
    {
        $algo = new A192KWAlgorithm(self::KEY_192);
        $this->assertInstanceOf(AESKWAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     */
    public function testAlgoParamValue(AESKWAlgorithm $algo)
    {
        $this->assertEquals(JWA::ALGO_A192KW, $algo->algorithmParamValue());
    }

    /**
     * @depends testCreate
     */
    public function testEncrypt(AESKWAlgorithm $algo)
    {
        $data = $algo->encrypt(self::CEK_192);
        $this->assertNotEquals(self::CEK_192, $data);
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
        $this->assertEquals(self::CEK_192, $cek);
    }
}
