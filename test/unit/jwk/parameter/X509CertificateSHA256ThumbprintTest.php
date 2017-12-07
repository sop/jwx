<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\X509CertificateSHA256ThumbprintParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
 */
class JWKX509CertificateSHA256ThumbprintParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = X509CertificateSHA256ThumbprintParameter::fromString(
            hash("sha256", "test", true));
        $this->assertInstanceOf(X509CertificateSHA256ThumbprintParameter::class,
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
            JWKParameter::PARAM_X509_CERTIFICATE_SHA256_THUMBPRINT,
            $param->name());
    }
}
