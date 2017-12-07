<?php

use JWX\JWT\Parameter\AuthenticationTagParameter;
use JWX\JWT\Parameter\JWTParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group parameter
 */
class AuthenticationTagParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = AuthenticationTagParameter::fromString("abcdef");
        $this->assertInstanceOf(AuthenticationTagParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_AUTHENTICATION_TAG,
            $param->name());
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testCreateFail()
    {
        new AuthenticationTagParameter("\0");
    }
}
