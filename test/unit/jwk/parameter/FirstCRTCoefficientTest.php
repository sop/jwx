<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\FirstCRTCoefficientParameter;
use Sop\JWX\JWK\Parameter\JWKParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
 */
class FirstCRTCoefficientParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = FirstCRTCoefficientParameter::fromNumber(123);
        $this->assertInstanceOf(FirstCRTCoefficientParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_FIRST_CRT_COEFFICIENT,
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
