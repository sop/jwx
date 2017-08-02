<?php

use JWX\JWK\Parameter\CurveParameter;
use JWX\JWK\Parameter\JWKParameter;

/**
 * @group jwk
 * @group parameter
 */
class CurveParameterTest extends PHPUnit_Framework_TestCase
{
    const OID_P256 = "1.2.840.10045.3.1.7";
    
    public function testCreate()
    {
        $param = new CurveParameter(CurveParameter::CURVE_P256);
        $this->assertInstanceOf(CurveParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
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
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testUnsupportedCurveOID()
    {
        CurveParameter::fromOID("1.3.6.1.3");
    }
    
    public function testNameToOID()
    {
        $oid = CurveParameter::nameToOID("P-256");
        $this->assertEquals(self::OID_P256, $oid);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testNameToOIDUnsupported()
    {
        CurveParameter::nameToOID("nope");
    }
    
    /**
     * @depends testCreate
     *
     * @param CurveParameter $param
     */
    public function testKeySizeBits(CurveParameter $param)
    {
        $this->assertEquals(256, $param->keySizeBits());
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testKeySizeBitsUnknownFail()
    {
        $param = new CurveParameter("fail");
        $param->keySizeBits();
    }
}
