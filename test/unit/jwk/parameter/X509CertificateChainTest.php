<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\X509CertificateChainParameter;
use JWX\Util\Base64;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
 */
class JWKX509CertificateChainParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new X509CertificateChainParameter(Base64::encode("\x5\0"));
        $this->assertInstanceOf(X509CertificateChainParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_X509_CERTIFICATE_CHAIN,
            $param->name());
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testCreateFail()
    {
        new X509CertificateChainParameter("\0");
    }
}
