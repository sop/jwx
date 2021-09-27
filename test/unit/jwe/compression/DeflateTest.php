<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\CompressionAlgorithm;
use Sop\JWX\JWE\CompressionAlgorithm\DeflateAlgorithm;
use Sop\JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use Sop\JWX\JWE\JWE;
use Sop\JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use Sop\JWX\JWT\JWT;

/**
 * @group jwe
 * @group compression
 *
 * @internal
 */
class DeflateTest extends TestCase
{
    const PAYLOAD = 'My hovercraft is full of eels.';
    const CEK_A128 = '123456789 123456789 123456789 12';

    public function testCreate()
    {
        $algo = new DeflateAlgorithm();
        $this->assertInstanceOf(CompressionAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     *
     * @param CompressionAlgorithm $algo
     */
    public function testCompressionParamValue(CompressionAlgorithm $algo)
    {
        $this->assertEquals(JWA::ALGO_DEFLATE, $algo->compressionParamValue());
    }

    /**
     * @depends testCreate
     *
     * @param CompressionAlgorithm $algo
     */
    public function testCompress(CompressionAlgorithm $algo)
    {
        $data = $algo->compress(self::PAYLOAD);
        $this->assertIsString($data);
        return $data;
    }

    /**
     * @depends testCreate
     * @depends testCompress
     *
     * @param CompressionAlgorithm $algo
     * @param string               $data
     */
    public function testDecompress(CompressionAlgorithm $algo, $data)
    {
        $payload = $algo->decompress($data);
        $this->assertEquals(self::PAYLOAD, $payload);
    }

    /**
     * @depends testCreate
     *
     * @param CompressionAlgorithm $algo
     */
    public function testEncrypt(CompressionAlgorithm $algo)
    {
        $key_algo = new DirectCEKAlgorithm(self::CEK_A128);
        $jwe = JWE::encrypt(self::PAYLOAD, $key_algo,
            new A128CBCHS256Algorithm(), $algo);
        $this->assertInstanceOf(JWE::class, $jwe);
        return $jwe->toCompact();
    }

    /**
     * @depends testEncrypt
     *
     * @param string $token
     */
    public function testDecrypt($token)
    {
        $jwt = new JWT($token);
        $key_algo = new DirectCEKAlgorithm(self::CEK_A128);
        $payload = $jwt->JWE()->decrypt($key_algo, new A128CBCHS256Algorithm());
        $this->assertEquals(self::PAYLOAD, $payload);
    }

    public function testCreateInvalidLevel()
    {
        $this->expectException(\DomainException::class);
        new DeflateAlgorithm(10);
    }

    /**
     * @depends testCreate
     *
     * @param CompressionAlgorithm $algo
     */
    public function testDecompressFail(CompressionAlgorithm $algo)
    {
        $this->expectException(\RuntimeException::class);
        $algo->decompress("\0");
    }

    /**
     * @depends testCreate
     * @requires PHP < 8
     *
     * @param CompressionAlgorithm $algo
     */
    public function testCompressFail(CompressionAlgorithm $algo)
    {
        $obj = new ReflectionClass($algo);
        $prop = $obj->getProperty('_compressionLevel');
        $prop->setAccessible(true);
        $prop->setValue($algo, 10);
        $this->expectException(\RuntimeException::class);
        $algo->compress('test');
    }
    
    /**
     * @depends testCreate
     * @requires PHP >= 8
     *
     * @param CompressionAlgorithm $algo
     */
    public function testCompressFailPhp8(CompressionAlgorithm $algo)
    {
        $obj = new ReflectionClass($algo);
        $prop = $obj->getProperty('_compressionLevel');
        $prop->setAccessible(true);
        $prop->setValue($algo, 10);
        $this->expectException(\ValueError::class);
        $algo->compress('test');
    }
}
