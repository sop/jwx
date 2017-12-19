<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\X509URLParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
 */
class JWKX509URLParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new X509URLParameter("https://example.com/");
        $this->assertInstanceOf(X509URLParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_X509_URL, $param->name());
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
