<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\SecondPrimeFactorParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
 */
class SecondPrimeFactorParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = SecondPrimeFactorParameter::fromNumber(123);
        $this->assertInstanceOf(SecondPrimeFactorParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_SECOND_PRIME_FACTOR,
            $param->name());
    }
}
