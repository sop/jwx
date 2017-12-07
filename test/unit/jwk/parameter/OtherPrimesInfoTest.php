<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\OtherPrimesInfoParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
 */
class OtherPrimesInfoParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new OtherPrimesInfoParameter();
        $this->assertInstanceOf(OtherPrimesInfoParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_OTHER_PRIMES_INFO,
            $param->name());
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testFromJSONValue(JWKParameter $param)
    {
        $param = OtherPrimesInfoParameter::fromJSONValue($param->value());
        $this->assertInstanceOf(OtherPrimesInfoParameter::class, $param);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testFromJSONValueFail()
    {
        OtherPrimesInfoParameter::fromJSONValue(null);
    }
}
