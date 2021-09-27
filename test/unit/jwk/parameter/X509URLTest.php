<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\X509URLParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
 */
class JWKX509URLParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new X509URLParameter('https://example.com/');
        $this->assertInstanceOf(X509URLParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_X509_URL, $param->name());
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
