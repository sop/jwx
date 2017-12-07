<?php

use JWX\JWA\JWA;
use JWX\JWS\Algorithm\NoneAlgorithm;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\JWTParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group parameter
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
     *
     * @param JWTParameter $param
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
