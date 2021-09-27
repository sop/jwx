<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use Sop\JWX\JWE\KeyManagementAlgorithm;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwe
 * @group key
 *
 * @internal
 */
class DirectCEKTest extends TestCase
{
    public const KEY_128 = '123456789 123456';

    public function testCreate()
    {
        $algo = new DirectCEKAlgorithm(self::KEY_128);
        $this->assertInstanceOf(DirectCEKAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     */
    public function testCEK(DirectCEKAlgorithm $algo)
    {
        $this->assertEquals(self::KEY_128, $algo->cek());
    }

    /**
     * @depends testCreate
     */
    public function testAlgoValue(DirectCEKAlgorithm $algo)
    {
        $this->assertEquals(JWA::ALGO_DIR, $algo->algorithmParamValue());
    }

    /**
     * @depends testCreate
     */
    public function testHeaderParameters(KeyManagementAlgorithm $algo)
    {
        $params = $algo->headerParameters();
        $this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
    }

    /**
     * @depends testCreate
     */
    public function testEncrypt(DirectCEKAlgorithm $algo)
    {
        $data = $algo->encrypt(self::KEY_128);
        $this->assertEquals('', $data);
        return $data;
    }

    /**
     * @depends testCreate
     * @depends testEncrypt
     *
     * @param mixed $data
     */
    public function testDecrypt(DirectCEKAlgorithm $algo, $data)
    {
        $cek = $algo->decrypt($data);
        $this->assertEquals(self::KEY_128, $cek);
    }

    /**
     * @depends testCreate
     */
    public function testEncryptFail(DirectCEKAlgorithm $algo)
    {
        $this->expectException(\LogicException::class);
        $algo->encrypt('fail');
    }

    /**
     * @depends testCreate
     */
    public function testDecryptFail(DirectCEKAlgorithm $algo)
    {
        $this->expectException(\UnexpectedValueException::class);
        $algo->decrypt('x');
    }

    /**
     * @depends testCreate
     */
    public function testCEKForEncryption(DirectCEKAlgorithm $algo)
    {
        $cek = $algo->cekForEncryption(strlen(self::KEY_128));
        $this->assertEquals(self::KEY_128, $cek);
    }

    /**
     * @depends testCreate
     */
    public function testCEKForEncryptionFail(DirectCEKAlgorithm $algo)
    {
        $this->expectException(\UnexpectedValueException::class);
        $algo->cekForEncryption(1);
    }

    public function testFromJWK()
    {
        $jwk = SymmetricKeyJWK::fromKey(self::KEY_128);
        $header = new Header(new AlgorithmParameter(JWA::ALGO_DIR));
        $algo = DirectCEKAlgorithm::fromJWK($jwk, $header);
        $this->assertInstanceOf(DirectCEKAlgorithm::class, $algo);
    }

    public function testFromJWKInvalidAlgo()
    {
        $jwk = SymmetricKeyJWK::fromKey(self::KEY_128);
        $header = new Header(new AlgorithmParameter(JWA::ALGO_A128KW));
        $this->expectException(\UnexpectedValueException::class);
        DirectCEKAlgorithm::fromJWK($jwk, $header);
    }
}
