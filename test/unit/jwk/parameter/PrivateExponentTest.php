<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\PrivateExponentParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
 */
class PrivateExponentParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = PrivateExponentParameter::fromNumber(123);
        $this->assertInstanceOf(PrivateExponentParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_PRIVATE_EXPONENT, $param->name());
    }
}
