<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\XCoordinateParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
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
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_X_COORDINATE, $param->name());
    }

    /**
     * @depends testCreate
     */
    public function testCoordinateOctets(XCoordinateParameter $param)
    {
        $this->assertEquals("\xff\x88", $param->coordinateOctets());
    }

    /**
     * @depends testCreate
     */
    public function testFromNameAndValue(JWKParameter $param)
    {
        $p = JWKParameter::fromNameAndValue($param->name(), $param->value());
        $this->assertEquals($p, $param);
    }
}
