<?php

use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\TypeParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group parameter
 */
class TypeParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new TypeParameter("example");
        $this->assertInstanceOf(TypeParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_TYPE, $param->name());
    }
}
