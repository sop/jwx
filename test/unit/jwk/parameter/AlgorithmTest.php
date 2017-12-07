<?php

use JWX\JWA\JWA;
use JWX\JWK\Parameter\AlgorithmParameter;
use JWX\JWK\Parameter\JWKParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
 */
class JWKAlgorithmParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new AlgorithmParameter(JWA::ALGO_A128CBC_HS256);
        $this->assertInstanceOf(AlgorithmParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_ALGORITHM, $param->name());
    }
}
