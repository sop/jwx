<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\ModulusParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
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
