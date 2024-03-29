<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\X509CertificateSHA1ThumbprintParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
 */
class JWKX509CertificateSHA1ThumbprintParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = X509CertificateSHA1ThumbprintParameter::fromString(
            sha1('test', true));
        $this->assertInstanceOf(X509CertificateSHA1ThumbprintParameter::class,
            $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(
            JWKParameter::PARAM_X509_CERTIFICATE_SHA1_THUMBPRINT, $param->name());
    }

    /**
     * @depends testCreate
     */
    public function testFromNameAndValue(JWKParameter $param)
    {
        $p = JWKParameter::fromNameAndValue($param->name(), $param->value());
        $this->assertEquals($p, $param);
    }
}
