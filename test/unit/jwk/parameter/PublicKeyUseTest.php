<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\PublicKeyUseParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
 */
class PublicKeyUseParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new PublicKeyUseParameter(PublicKeyUseParameter::USE_SIGNATURE);
        $this->assertInstanceOf(PublicKeyUseParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_PUBLIC_KEY_USE, $param->name());
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
