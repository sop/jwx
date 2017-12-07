<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\XCoordinateParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
 */
class XCoordinateParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = XCoordinateParameter::fromString("\xff\x88");
        $this->assertInstanceOf(XCoordinateParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_X_COORDINATE, $param->name());
    }
    
    /**
     * @depends testCreate
     *
     * @param XCoordinateParameter $param
     */
    public function testCoordinateOctets(XCoordinateParameter $param)
    {
        $this->assertEquals("\xff\x88", $param->coordinateOctets());
    }
}
