<?php

use JWX\JWK\Parameter\FirstCRTCoefficientParameter;
use JWX\JWK\Parameter\JWKParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
 */
class FirstCRTCoefficientParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = FirstCRTCoefficientParameter::fromNumber(123);
        $this->assertInstanceOf(FirstCRTCoefficientParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_FIRST_CRT_COEFFICIENT,
            $param->name());
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testFromNameAndValue(JWKParameter $param)
    {
        $p = JWKParameter::fromNameAndValue($param->name(), $param->value());
        $this->assertEquals($p, $param);
    }
}
