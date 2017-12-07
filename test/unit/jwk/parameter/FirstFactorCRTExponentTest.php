<?php

use JWX\JWK\Parameter\FirstFactorCRTExponentParameter;
use JWX\JWK\Parameter\JWKParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
 */
class FirstFactorCRTExponentParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = FirstFactorCRTExponentParameter::fromNumber(123);
        $this->assertInstanceOf(FirstFactorCRTExponentParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_FIRST_FACTOR_CRT_EXPONENT,
            $param->name());
    }
}
