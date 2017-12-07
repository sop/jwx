<?php

use JWX\JWT\Parameter\B64PayloadParameter;
use JWX\JWT\Parameter\JWTParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group parameter
 */
class B64PayloadParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new B64PayloadParameter(false);
        $this->assertInstanceOf(B64PayloadParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_BASE64URL_ENCODE_PAYLOAD,
            $param->name());
    }
}
