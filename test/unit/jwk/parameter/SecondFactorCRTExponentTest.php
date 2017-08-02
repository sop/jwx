<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\SecondFactorCRTExponentParameter;

/**
 * @group jwk
 * @group parameter
 */
class SecondFactorCRTExponentParameterTest extends PHPUnit_Framework_TestCase
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
