<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\X509CertificateSHA1ThumbprintParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
 */
class JWKX509CertificateSHA1ThumbprintParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = X509CertificateSHA1ThumbprintParameter::fromString(
            sha1("test", true));
        $this->assertInstanceOf(X509CertificateSHA1ThumbprintParameter::class,
            $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(
            JWKParameter::PARAM_X509_CERTIFICATE_SHA1_THUMBPRINT, $param->name());
    }
}
