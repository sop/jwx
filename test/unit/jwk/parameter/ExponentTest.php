<?php

use JWX\JWK\Parameter\ExponentParameter;
use JWX\JWK\Parameter\JWKParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
 */
class ExponentParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = ExponentParameter::fromNumber(123);
        $this->assertInstanceOf(ExponentParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_EXPONENT, $param->name());
    }
}
