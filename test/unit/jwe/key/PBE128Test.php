<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyAlgorithm\PBES2Algorithm;
use Sop\JWX\JWE\KeyAlgorithm\PBES2HS256A128KWAlgorithm;

/**
 * @group jwe
 * @group key
 *
 * @internal
 */
class PBES2A128KWTest extends TestCase
{
    const PASSWORD = 'password';
    const SALT = 'salt';
    const COUNT = 256;
    const KEY_128 = '123456789 123456';

    public function testCreate()
    {
        $algo = new PBES2HS256A128KWAlgorithm(self::PASSWORD, self::SALT, self::COUNT);
        $this->assertInstanceOf(PBES2Algorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     *
     * @param PBES2Algorithm $algo
     */
    public function testAlgoValue(PBES2Algorithm $algo)
    {
        $this->assertEquals(JWA::ALGO_PBES2_HS256_A128KW,
            $algo->algorithmParamValue());
    }

    /**
     * @depends testCreate
     *
     * @param PBES2Algorithm $algo
     */
    public function testEncrypt(PBES2Algorithm $algo)
    {
        $data = $algo->encrypt(self::KEY_128);
        $this->assertNotEquals(self::KEY_128, $data);
        return $data;
    }

    /**
     * @depends testCreate
     * @depends testEncrypt
     *
     * @param PBES2Algorithm $algo
     * @param mixed          $data
     */
    public function testDecrypt(PBES2Algorithm $algo, $data)
    {
        $key = $algo->decrypt($data);
        $this->assertEquals(self::KEY_128, $key);
    }
}
