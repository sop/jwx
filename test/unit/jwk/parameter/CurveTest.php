<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\CurveParameter;
use Sop\JWX\JWK\Parameter\JWKParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
 */
class CurveParameterTest extends TestCase
{
    public const OID_P256 = '1.2.840.10045.3.1.7';

    public function testCreate()
    {
        $param = new CurveParameter(CurveParameter::CURVE_P256);
        $this->assertInstanceOf(CurveParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_CURVE, $param->name());
    }

    public function testFromOID()
    {
        $param = CurveParameter::fromOID(self::OID_P256);
        $this->assertInstanceOf(CurveParameter::class, $param);
    }

    public function testUnsupportedCurveOID()
    {
        $this->expectException(\UnexpectedValueException::class);
        CurveParameter::fromOID('1.3.6.1.3');
    }

    public function testNameToOID()
    {
        $oid = CurveParameter::nameToOID('P-256');
        $this->assertEquals(self::OID_P256, $oid);
    }

    public function testNameToOIDUnsupported()
    {
        $this->expectException(\UnexpectedValueException::class);
        CurveParameter::nameToOID('nope');
    }

    /**
     * @depends testCreate
     */
    public function testKeySizeBits(CurveParameter $param)
    {
        $this->assertEquals(256, $param->keySizeBits());
    }

    public function testKeySizeBitsUnknownFail()
    {
        $param = new CurveParameter('fail');
        $this->expectException(\UnexpectedValueException::class);
        $param->keySizeBits();
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
