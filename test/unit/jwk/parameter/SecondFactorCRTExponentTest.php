<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\SecondFactorCRTExponentParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
 */
class SecondFactorCRTExponentParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = SecondFactorCRTExponentParameter::fromNumber(123);
        $this->assertInstanceOf(SecondFactorCRTExponentParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_SECOND_FACTOR_CRT_EXPONENT,
            $param->name());
    }
}
