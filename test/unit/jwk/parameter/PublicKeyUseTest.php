<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\PublicKeyUseParameter;

/**
 * @group jwk
 * @group parameter
 */
class PublicKeyUseParameterTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $param = new PublicKeyUseParameter(PublicKeyUseParameter::USE_SIGNATURE);
        $this->assertInstanceOf(PublicKeyUseParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_PUBLIC_KEY_USE, $param->name());
    }
}
