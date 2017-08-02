<?php

use JWX\JWT\Parameter\InitializationVectorParameter;
use JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwt
 * @group parameter
 */
class InitializationVectorParameterTest extends PHPUnit_Framework_TestCase
{
    const IV = "abcdef";
    
    public function testCreate()
    {
        $param = InitializationVectorParameter::fromString(self::IV);
        $this->assertInstanceOf(InitializationVectorParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_INITIALIZATION_VECTOR,
            $param->name());
    }
    
    /**
     * @depends testCreate
     *
     * @param InitializationVectorParameter $param
     */
    public function testIV(InitializationVectorParameter $param)
    {
        $this->assertEquals(self::IV, $param->initializationVector());
    }
}
