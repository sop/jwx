<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\YCoordinateParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
 */
class YCoordinateParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = YCoordinateParameter::fromString("\xff\x88");
        $this->assertInstanceOf(YCoordinateParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_Y_COORDINATE, $param->name());
    }

    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testFromNameAndValue(JWKParameter $param)
    {
        $p = JWKParameter::fromNameAndValue($param->name(), $param->value());
        $this->assertEquals($p, $param);
    }
}
