<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\SecondFactorCRTExponentParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
 */
class SecondFactorCRTExponentParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = SecondFactorCRTExponentParameter::fromNumber(123);
        $this->assertInstanceOf(SecondFactorCRTExponentParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_SECOND_FACTOR_CRT_EXPONENT,
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
