<?php

use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\PBES2SaltInputParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group parameter
 */
class PBES2SaltInputParameterTest extends TestCase
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
     * @param PBES2SaltInputParameter $param
     */
    public function testSaltInput(PBES2SaltInputParameter $param)
    {
        $this->assertEquals(self::SALT_INPUT, $param->saltInput());
    }
}
