<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\FirstFactorCRTExponentParameter;
use Sop\JWX\JWK\Parameter\JWKParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
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
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_FIRST_FACTOR_CRT_EXPONENT,
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
