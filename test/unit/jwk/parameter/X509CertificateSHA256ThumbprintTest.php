<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\X509CertificateSHA256ThumbprintParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
 */
class JWKX509CertificateSHA256ThumbprintParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = X509CertificateSHA256ThumbprintParameter::fromString(
            hash('sha256', 'test', true));
        $this->assertInstanceOf(X509CertificateSHA256ThumbprintParameter::class,
            $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(
            JWKParameter::PARAM_X509_CERTIFICATE_SHA256_THUMBPRINT,
            $param->name());
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
