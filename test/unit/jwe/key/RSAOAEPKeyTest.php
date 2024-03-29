<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyAlgorithm\RSAESKeyAlgorithm;
use Sop\JWX\JWE\KeyAlgorithm\RSAESOAEPAlgorithm;
use Sop\JWX\JWE\KeyManagementAlgorithm;
use Sop\JWX\JWK\RSA\RSAPrivateKeyJWK;

/**
 * @group jwe
 * @group key
 *
 * @internal
 */
class RSAOAEPKeyTest extends TestCase
{
    public const CEK = '123456789 123456';

    private static $_publicKey;

    private static $_privateKey;

    public static function setUpBeforeClass(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        self::$_privateKey = RSAPrivateKeyJWK::fromPEM($pem);
        self::$_publicKey = self::$_privateKey->publicKey();
    }

    public static function tearDownAfterClass(): void
    {
        self::$_publicKey = null;
        self::$_privateKey = null;
    }

    public function testCreate()
    {
        $algo = RSAESOAEPAlgorithm::fromPrivateKey(self::$_privateKey);
        $this->assertInstanceOf(RSAESKeyAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     */
    public function testAlgoValue(KeyManagementAlgorithm $algo)
    {
        $this->assertEquals(JWA::ALGO_RSA_OAEP, $algo->algorithmParamValue());
    }

    /**
     * @depends testCreate
     */
    public function testEncrypt(RSAESKeyAlgorithm $algo)
    {
        $data = $algo->encrypt(self::CEK);
        $this->assertNotEquals(self::CEK, $data);
        return $data;
    }

    /**
     * @depends testCreate
     * @depends testEncrypt
     *
     * @param string $data
     */
    public function testDecrypt(RSAESKeyAlgorithm $algo, $data)
    {
        $cek = $algo->decrypt($data);
        $this->assertEquals(self::CEK, $cek);
    }
}
