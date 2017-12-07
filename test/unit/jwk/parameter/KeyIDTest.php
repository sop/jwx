<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\KeyIDParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
 */
class JWKKeyIDParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new KeyIDParameter("test");
        $this->assertInstanceOf(KeyIDParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_KEY_ID, $param->name());
    }
}
