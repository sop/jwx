<?php

use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\X509URLParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group parameter
 */
class X509URLParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new X509URLParameter("https://example.com/");
        $this->assertInstanceOf(X509URLParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_X509_URL, $param->name());
    }
}
