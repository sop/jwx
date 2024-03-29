<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Parameter\CriticalParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class CriticalParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new CriticalParameter('typ', 'cty');
        $this->assertInstanceOf(CriticalParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_CRITICAL, $param->name());
    }

    /**
     * @depends testCreate
     */
    public function testNames(CriticalParameter $param)
    {
        $this->assertEquals(['typ', 'cty'], $param->names());
    }

    /**
     * @depends testCreate
     */
    public function testHas(CriticalParameter $param)
    {
        $this->assertTrue($param->has('typ'));
    }

    /**
     * @depends testCreate
     */
    public function testHasNot(CriticalParameter $param)
    {
        $this->assertFalse($param->has('nope'));
    }

    /**
     * @depends testCreate
     */
    public function testWithName(CriticalParameter $param)
    {
        $param = $param->withParamName('test');
        $this->assertCount(3, $param->names());
    }

    public function testFromJSON()
    {
        $param = CriticalParameter::fromJSONValue(['test']);
        $this->assertInstanceOf(CriticalParameter::class, $param);
    }

    public function testFromInvalidJSON()
    {
        $this->expectException(\UnexpectedValueException::class);
        CriticalParameter::fromJSONValue(null);
    }
}
