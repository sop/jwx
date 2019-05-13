<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\ModulusParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
 */
class ModulusParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = ModulusParameter::fromNumber(123);
        $this->assertInstanceOf(ModulusParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_MODULUS, $param->name());
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
