<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\OtherPrimesInfoParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
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

    public function testFromJSONValueFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        OtherPrimesInfoParameter::fromJSONValue(null);
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
