<?php

use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\PBES2CountParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group parameter
 */
class PBES2CountParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new PBES2CountParameter(1024);
        $this->assertInstanceOf(PBES2CountParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_PBES2_COUNT, $param->name());
    }
}
