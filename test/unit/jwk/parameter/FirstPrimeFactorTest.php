<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\FirstPrimeFactorParameter;
use Sop\JWX\JWK\Parameter\JWKParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
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
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_FIRST_PRIME_FACTOR,
            $param->name());
    }

    /**
     * @depends testCreate
     */
    public function testFromNameAndValue(JWKParameter $param)
    {
        $p = JWKParameter::fromNameAndValue($param->name(), $param->value());
        $this->assertEquals($p, $param);
    }
}
