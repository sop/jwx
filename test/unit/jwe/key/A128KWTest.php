<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyAlgorithm\A128KWAlgorithm;
use Sop\JWX\JWE\KeyAlgorithm\AESKWAlgorithm;

/**
 * @group jwe
 * @group key
 *
 * @internal
 */
class A128KWTest extends TestCase
{
    const KEY_128 = '123456789 123456';
    const CEK_128 = '987654321 987654';

    public function testCreate()
    {
        $algo = new A128KWAlgorithm(self::KEY_128);
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
        $this->assertEquals(JWA::ALGO_A128KW, $algo->algorithmParamValue());
    }

    /**
     * @depends testCreate
     *
     * @param AESKWAlgorithm $algo
     */
    public function testEncrypt(AESKWAlgorithm $algo)
    {
        $data = $algo->encrypt(self::CEK_128);
        $this->assertNotEquals(self::CEK_128, $data);
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
        $this->assertEquals(self::CEK_128, $cek);
    }

    public function testInvalidKEKLength()
    {
        $this->expectException(\LengthException::class);
        new A128KWAlgorithm(self::KEY_128 . 'x');
    }

    /**
     * @depends testCreate
     *
     * @param AESKWAlgorithm $algo
     */
    public function testInvalidCEKLength(AESKWAlgorithm $algo)
    {
        $this->expectException(\UnexpectedValueException::class);
        $algo->encrypt(self::CEK_128 . 'x');
    }
}
