<?php

use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\PBES2SaltInputParameter;

/**
 * @group jwt
 * @group parameter
 */
class PBES2SaltInputParameterTest extends PHPUnit_Framework_TestCase
{
    const SALT_INPUT = "abcdef";
    
    public function testCreate()
    {
        $param = PBES2SaltInputParameter::fromString(self::SALT_INPUT);
        $this->assertInstanceOf(PBES2SaltInputParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_PBES2_SALT_INPUT, $param->name());
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testSaltInput(PBES2SaltInputParameter $param)
    {
        $this->assertEquals(self::SALT_INPUT, $param->saltInput());
    }
}
