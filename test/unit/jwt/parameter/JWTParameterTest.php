<?php

use JWX\JWT\Parameter\JWTParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group parameter
 */
class JWTParameterTest extends TestCase
{
    public function testCreateUnknown()
    {
        $param = JWTParameter::fromNameAndValue("unknown", "value");
        $this->assertInstanceOf(JWTParameter::class, $param);
    }
    
    /**
     * @expectedException BadMethodCallException
     */
    public function testFromJSONValueBadCall()
    {
        JWTParameter::fromJSONValue(null);
    }
}
