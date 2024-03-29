<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Parameter\B64PayloadParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class B64PayloadParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new B64PayloadParameter(false);
        $this->assertInstanceOf(B64PayloadParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_BASE64URL_ENCODE_PAYLOAD, $param->name());
    }
}
