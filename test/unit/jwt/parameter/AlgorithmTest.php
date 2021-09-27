<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWS\Algorithm\NoneAlgorithm;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class JWTAlgorithmParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new AlgorithmParameter(JWA::ALGO_NONE);
        $this->assertInstanceOf(AlgorithmParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_ALGORITHM, $param->name());
    }

    public function testFromAlgo()
    {
        $param = AlgorithmParameter::fromAlgorithm(new NoneAlgorithm());
        $this->assertInstanceOf(AlgorithmParameter::class, $param);
    }
}
