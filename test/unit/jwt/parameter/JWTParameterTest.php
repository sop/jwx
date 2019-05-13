<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class JWTParameterTest extends TestCase
{
    public function testCreateUnknown()
    {
        $param = JWTParameter::fromNameAndValue('unknown', 'value');
        $this->assertInstanceOf(JWTParameter::class, $param);
    }

    public function testFromJSONValueBadCall()
    {
        $this->expectException(\BadMethodCallException::class);
        JWTParameter::fromJSONValue(null);
    }
}
