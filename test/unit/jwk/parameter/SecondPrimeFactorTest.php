<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\SecondPrimeFactorParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
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
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_SECOND_PRIME_FACTOR,
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
