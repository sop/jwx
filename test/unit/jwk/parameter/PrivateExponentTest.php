<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\PrivateExponentParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
 */
class PrivateExponentParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = PrivateExponentParameter::fromNumber(123);
        $this->assertInstanceOf(PrivateExponentParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_PRIVATE_EXPONENT, $param->name());
    }
}
