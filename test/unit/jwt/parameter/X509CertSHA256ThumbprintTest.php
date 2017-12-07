<?php

use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\X509CertificateSHA256ThumbprintParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group parameter
 */
class X509CertificateSHA256ThumbprintParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = X509CertificateSHA256ThumbprintParameter::fromString("abcdef");
        $this->assertInstanceOf(X509CertificateSHA256ThumbprintParameter::class,
            $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(
            JWTParameter::PARAM_X509_CERTIFICATE_SHA256_THUMBPRINT,
            $param->name());
    }
}
