<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Parameter\JWTParameter;
use Sop\JWX\JWT\Parameter\X509CertificateSHA1ThumbprintParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class X509CertificateSHA1ThumbprintParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = X509CertificateSHA1ThumbprintParameter::fromString('abcdef');
        $this->assertInstanceOf(X509CertificateSHA1ThumbprintParameter::class,
            $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(
            JWTParameter::PARAM_X509_CERTIFICATE_SHA1_THUMBPRINT, $param->name());
    }
}
