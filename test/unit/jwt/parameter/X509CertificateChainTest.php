<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Parameter\JWTParameter;
use Sop\JWX\JWT\Parameter\X509CertificateChainParameter;
use Sop\JWX\Util\Base64;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class X509CertificateChainParameterTest extends TestCase
{
    public function testCreate()
    {
        $cert = Base64::encode('certdata');
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

    public function testCreateFail()
    {
        $cert = "\0";
        $this->expectException(\UnexpectedValueException::class);
        new X509CertificateChainParameter($cert);
    }

    public function testFromJSONFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        X509CertificateChainParameter::fromJSONValue(null);
    }
}
