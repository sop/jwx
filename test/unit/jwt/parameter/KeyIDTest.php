<?php

use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\KeyIDParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group parameter
 */
class JWTKeyIDParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new KeyIDParameter(false);
        $this->assertInstanceOf(KeyIDParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_KEY_ID, $param->name());
    }
}
