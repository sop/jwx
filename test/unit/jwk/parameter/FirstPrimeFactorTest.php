<?php

use JWX\JWK\Parameter\FirstPrimeFactorParameter;
use JWX\JWK\Parameter\JWKParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
 */
class FirstPrimeFactorParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = FirstPrimeFactorParameter::fromNumber(123);
        $this->assertInstanceOf(FirstPrimeFactorParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_FIRST_PRIME_FACTOR,
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
