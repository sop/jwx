<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\CompressionAlgorithm\DeflateAlgorithm;
use Sop\JWX\JWT\Parameter\CompressionAlgorithmParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class CompressionAlgorithmParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new CompressionAlgorithmParameter(JWA::ALGO_DEFLATE);
        $this->assertInstanceOf(CompressionAlgorithmParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_COMPRESSION_ALGORITHM, $param->name());
    }

    public function testFromAlgo()
    {
        $param = CompressionAlgorithmParameter::fromAlgorithm(new DeflateAlgorithm());
        $this->assertInstanceOf(CompressionAlgorithmParameter::class, $param);
    }
}
