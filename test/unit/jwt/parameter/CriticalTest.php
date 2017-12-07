<?php

use JWX\JWT\Parameter\CriticalParameter;
use JWX\JWT\Parameter\JWTParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group parameter
 */
class CriticalParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new CriticalParameter("typ", "cty");
        $this->assertInstanceOf(CriticalParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_CRITICAL, $param->name());
    }
    
    /**
     * @depends testCreate
     *
     * @param CriticalParameter $param
     */
    public function testNames(CriticalParameter $param)
    {
        $this->assertEquals(["typ", "cty"], $param->names());
    }
    
    /**
     * @depends testCreate
     *
     * @param CriticalParameter $param
     */
    public function testHas(CriticalParameter $param)
    {
        $this->assertTrue($param->has("typ"));
    }
    
    /**
     * @depends testCreate
     *
     * @param CriticalParameter $param
     */
    public function testHasNot(CriticalParameter $param)
    {
        $this->assertFalse($param->has("nope"));
    }
    
    /**
     * @depends testCreate
     *
     * @param CriticalParameter $param
     */
    public function testWithName(CriticalParameter $param)
    {
        $param = $param->withParamName("test");
        $this->assertCount(3, $param->names());
    }
    
    public function testFromJSON()
    {
        $param = CriticalParameter::fromJSONValue(["test"]);
        $this->assertInstanceOf(CriticalParameter::class, $param);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testFromInvalidJSON()
    {
        CriticalParameter::fromJSONValue(null);
    }
}
