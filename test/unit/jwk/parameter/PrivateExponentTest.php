<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\PrivateExponentParameter;

/**
 * @group jwk
 * @group parameter
 */
class PrivateExponentParameterTest extends PHPUnit_Framework_TestCase
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
