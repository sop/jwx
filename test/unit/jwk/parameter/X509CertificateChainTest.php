<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\X509CertificateChainParameter;
use Sop\JWX\Util\Base64;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
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
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_X509_CERTIFICATE_CHAIN,
            $param->name());
    }

    public function testCreateFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        new X509CertificateChainParameter("\0");
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
