<?php

use JWX\JWA\JWA;
use JWX\JWE\KeyAlgorithm\PBES2Algorithm;
use JWX\JWE\KeyAlgorithm\PBES2HS384A192KWAlgorithm;
use PHPUnit\Framework\TestCase;

/**
 * @group jwe
 * @group key
 */
class PBES2A192KWTest extends TestCase
{
    const PASSWORD = "password";
    const SALT = "salt";
    const COUNT = 256;
    const KEY_192 = "123456789 123456789 1234";
    
    public function testCreate()
    {
        $algo = new PBES2HS384A192KWAlgorithm(self::PASSWORD, self::SALT,
            self::COUNT);
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
        $this->assertEquals(JWA::ALGO_PBES2_HS384_A192KW,
            $algo->algorithmParamValue());
    }
    
    /**
     * @depends testCreate
     *
     * @param PBES2Algorithm $algo
     */
    public function testEncrypt(PBES2Algorithm $algo)
    {
        $data = $algo->encrypt(self::KEY_192);
        $this->assertNotEquals(self::KEY_192, $data);
        return $data;
    }
    
    /**
     * @depends testCreate
     * @depends testEncrypt
     *
     * @param PBES2Algorithm $algo
     */
    public function testDecrypt(PBES2Algorithm $algo, $data)
    {
        $key = $algo->decrypt($data);
        $this->assertEquals(self::KEY_192, $key);
    }
}