<?php

use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\X509CertificateSHA1ThumbprintParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group parameter
 */
class X509CertificateSHA1ThumbprintParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = X509CertificateSHA1ThumbprintParameter::fromString("abcdef");
        $this->assertInstanceOf(X509CertificateSHA1ThumbprintParameter::class,
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
            JWTParameter::PARAM_X509_CERTIFICATE_SHA1_THUMBPRINT, $param->name());
    }
}
