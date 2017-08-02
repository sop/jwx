<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\X509URLParameter;

/**
 * @group jwk
 * @group parameter
 */
class JWKX509URLParameterTest extends PHPUnit_Framework_TestCase
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
}
