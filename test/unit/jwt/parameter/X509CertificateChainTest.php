<?php

use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\X509CertificateChainParameter;
use JWX\Util\Base64;

/**
 * @group jwt
 * @group parameter
 */
class X509CertificateChainParameterTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $cert = Base64::encode("certdata");
        $param = new X509CertificateChainParameter($cert);
        $this->assertInstanceOf(X509CertificateChainParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_X509_CERTIFICATE_CHAIN,
            $param->name());
    }
    
    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testFromJSONValue(JWTParameter $param)
    {
        $param = X509CertificateChainParameter::fromJSONValue($param->value());
        $this->assertInstanceOf(X509CertificateChainParameter::class, $param);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testCreateFail()
    {
        $cert = "\0";
        new X509CertificateChainParameter($cert);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testFromJSONFail()
    {
        X509CertificateChainParameter::fromJSONValue(null);
    }
}
