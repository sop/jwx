<?php

use JWX\JWT\Parameter\JWKSetURLParameter;
use JWX\JWT\Parameter\JWTParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group parameter
 */
class JWKSetURLParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new JWKSetURLParameter("https://example.com/");
        $this->assertInstanceOf(JWKSetURLParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_JWK_SET_URL, $param->name());
    }
}
